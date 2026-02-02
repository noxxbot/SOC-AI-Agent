from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import logging
import hashlib
import json

from app.core.config import settings
from app.database.db import get_db, SessionLocal
from app.models.models import EndpointLog, ProcessedLog
from app.services.ai_service import AIService
from app.services.log_processing.pipeline import process_logs_batch
from app.services.correlation_scheduler import run_correlation_once
from app.services.alert_automation import run_detection_pipeline_task

router = APIRouter()
logger = logging.getLogger(__name__)


class LogIngestRequest(BaseModel):
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    timestamp: Optional[str] = None
    telemetry: Optional[Dict[str, Any]] = None
    logs: Optional[List[Dict[str, Any]]] = None
    body: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class LogIngestResponse(BaseModel):
    status: str
    received: int
    processed: int
    stored: int
    skipped_duplicates: int
    skipped_invalid: int


class LogRecord(BaseModel):
    event_id: str
    timestamp: Optional[str]
    agent_id: str
    hostname: Optional[str]
    log_source: Optional[str]
    event_type: Optional[str]
    severity_raw: Optional[str]
    raw: Optional[str]
    fields: Dict[str, Any]


class ProcessedLogRecord(BaseModel):
    id: int
    agent_id: str
    hostname: Optional[str]
    timestamp: Optional[str]
    category: str
    event_type: str
    severity_score: int
    message: Optional[str]
    raw: Optional[str]
    fields_json: Dict[str, Any]
    iocs_json: Dict[str, Any]
    tags_json: List[str]
    fingerprint: str
    created_at: Optional[str]
    mitre_matches: List[Dict[str, Any]] = Field(default_factory=list)
    ioc_intel: Dict[str, Any] = Field(default_factory=dict)
    ai_notes: Optional[Dict[str, Any]] = None


def parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except Exception:
        return None


def _safe_insert(db: Session, objects: List[Any]) -> Dict[str, int]:
    if not objects:
        return {"stored": 0, "skipped": 0}
    try:
        db.add_all(objects)
        db.commit()
        for obj in objects:
            db.refresh(obj)
        return {"stored": len(objects), "skipped": 0}
    except IntegrityError:
        db.rollback()
    stored = 0
    skipped = 0
    for obj in objects:
        try:
            db.add(obj)
            db.commit()
            db.refresh(obj)
            stored += 1
        except IntegrityError:
            db.rollback()
            skipped += 1
    return {"stored": stored, "skipped": skipped}


def _parse_json(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _should_auto_notes(log_payload: Dict[str, Any]) -> bool:
    mode = str(settings.AI_LOG_NOTES_MODE or "suspicious_only").strip().lower()
    if mode == "manual":
        return False
    if mode == "all":
        return True
    severity_score = int(log_payload.get("severity_score") or 0)
    fields = log_payload.get("fields") or {}
    mitre_matches = fields.get("mitre_matches") or log_payload.get("mitre_matches") or []
    ioc_intel = fields.get("ioc_intel") or log_payload.get("ioc_intel") or {}
    ioc_summary = ioc_intel.get("ioc_summary") or {}
    ioc_risk = str(ioc_summary.get("risk") or "").lower()
    tags = log_payload.get("tags") or []
    suspicious_tags = {
        "powershell",
        "encoded_command",
        "rundll32",
        "regsvr32",
        "certutil",
        "wmic",
        "schtasks"
    }
    has_suspicious_tag = any(
        str(t).lower().startswith("mitre:") or str(t).lower().startswith("ioc:") or str(t).lower() in suspicious_tags
        for t in tags
    )
    return (
        severity_score >= 60
        or bool(mitre_matches)
        or ioc_risk in {"suspicious", "malicious"}
        or has_suspicious_tag
    )


async def run_log_notes_task(processed_id: int) -> None:
    db = SessionLocal()
    try:
        log = db.query(ProcessedLog).filter(ProcessedLog.id == processed_id).first()
        if not log:
            return
        fields = _parse_json(log.fields_json, {})
        if isinstance(fields, dict) and fields.get("ai_notes"):
            return
        iocs = _parse_json(log.iocs_json, {})
        tags = _parse_json(log.tags_json, [])
        payload = {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "agent_id": log.agent_id,
            "hostname": log.hostname,
            "category": log.category,
            "event_type": log.event_type,
            "severity_score": log.severity_score,
            "message": log.message,
            "raw": log.raw,
            "fields": fields,
            "iocs": iocs,
            "tags": tags,
            "fingerprint": log.fingerprint
        }
        if not _should_auto_notes(payload):
            return
        ai_service = AIService()
        notes = await ai_service.generate_log_notes(payload)
        if not isinstance(fields, dict):
            fields = {}
        fields["ai_notes"] = notes
        log.fields_json = json.dumps(fields)
        db.add(log)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("log ai notes task failed", extra={"processed_id": processed_id})
    finally:
        db.close()


def _payload_to_dict(payload: LogIngestRequest) -> Dict[str, Any]:
    data = payload.dict(exclude_none=True)
    extras = {k: v for k, v in payload.__dict__.items() if k not in payload.__fields__}
    data.update(extras)
    return data


def _build_event_id(data: Dict[str, Any]) -> str:
    seed = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _extract_logs(payload_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    body = payload_data.get("body")
    if isinstance(body, dict):
        if isinstance(body.get("logs"), list):
            return body.get("logs") or []
        return [body]
    if isinstance(payload_data.get("logs"), list):
        return payload_data.get("logs") or []
    if isinstance(payload_data.get("logs"), dict):
        return [payload_data.get("logs")]
    return [payload_data]


def _normalize_incoming_log(log: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = str(log.get("agent_id") or defaults.get("agent_id") or "").strip()
    log_source = str(log.get("log_source") or log.get("source") or "").strip()
    event_type = str(log.get("event_type") or "").strip()
    hostname = str(log.get("hostname") or log.get("host") or defaults.get("hostname") or "").strip()
    timestamp = log.get("timestamp") or defaults.get("timestamp")
    if not timestamp or not parse_timestamp(str(timestamp)):
        timestamp = None

    fields_payload = log.get("fields")
    if not isinstance(fields_payload, dict):
        fields_payload = {}
    for key in [
        "user",
        "message",
        "query",
        "src_ip",
        "dst_ip",
        "dst_port",
        "process_name",
        "command_line",
        "count"
    ]:
        if log.get(key) is not None:
            fields_payload[key] = log.get(key)
    reserved = {
        "agent_id",
        "hostname",
        "host",
        "log_source",
        "source",
        "event_type",
        "timestamp",
        "message",
        "raw",
        "severity",
        "severity_raw",
        "fields",
        "event_id",
        "logs",
        "telemetry",
        "body"
    }
    for key, value in log.items():
        if key not in reserved and key not in fields_payload:
            fields_payload[key] = value

    event_id = log.get("event_id")
    if not event_id:
        event_id = _build_event_id(
            {
                "agent_id": agent_id,
                "hostname": hostname,
                "log_source": log_source,
                "event_type": event_type,
                "timestamp": timestamp,
                "message": log.get("message"),
                "raw": log.get("raw"),
                "fields": fields_payload
            }
        )
    severity_raw = log.get("severity_raw") or log.get("severity")

    return {
        "event_id": str(event_id),
        "agent_id": agent_id,
        "hostname": hostname,
        "log_source": log_source,
        "event_type": event_type,
        "timestamp": timestamp,
        "severity_raw": severity_raw,
        "raw": log.get("raw") or log.get("message") or "",
        "message": log.get("message") or "",
        "fields": fields_payload
    }


def _validate_required_log(log: Dict[str, Any]) -> Optional[str]:
    if not log.get("agent_id"):
        return "agent_id is required"
    if not log.get("log_source"):
        return "source is required"
    if not log.get("event_type"):
        return "event_type is required"
    if not log.get("hostname"):
        return "host is required"
    if not log.get("timestamp"):
        return "timestamp is required"
    return None


def _run_post_ingest_pipeline(processed_ids: List[int]) -> None:
    try:
        run_correlation_once()
    finally:
        run_detection_pipeline_task(processed_ids or None)


@router.post("/logs/ingest", response_model=LogIngestResponse)
async def ingest_logs(payload: LogIngestRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    payload_data = _payload_to_dict(payload)
    logger.info("ingest payload received", extra={"payload": payload_data})
    logs_input = _extract_logs(payload_data)
    if not isinstance(logs_input, list) or len(logs_input) == 0:
        raise HTTPException(status_code=422, detail="logs must be provided")

    defaults = {
        "agent_id": payload_data.get("agent_id") or (payload_data.get("body") or {}).get("agent_id"),
        "hostname": payload_data.get("hostname") or (payload_data.get("body") or {}).get("hostname") or (payload_data.get("body") or {}).get("host"),
        "timestamp": payload_data.get("timestamp") or (payload_data.get("body") or {}).get("timestamp")
    }
    normalized_logs: List[Dict[str, Any]] = []
    errors: List[str] = []
    for idx, log in enumerate(logs_input):
        if not isinstance(log, dict):
            errors.append(f"log[{idx}] must be an object")
            continue
        normalized = _normalize_incoming_log(log, defaults)
        error = _validate_required_log(normalized)
        if error:
            errors.append(f"log[{idx}]: {error}")
            continue
        normalized_logs.append(normalized)

    if errors:
        logger.warning("ingest validation failed", extra={"errors": errors})
        raise HTTPException(status_code=422, detail={"errors": errors})

    received = len(normalized_logs)
    skipped_invalid = 0
    event_ids = list({str(log.get("event_id")) for log in normalized_logs if log.get("event_id")})
    existing_event_ids = set()
    if event_ids:
        existing = db.query(EndpointLog.event_id).filter(EndpointLog.event_id.in_(event_ids)).all()
        existing_event_ids = {row[0] for row in existing}

    to_insert: List[EndpointLog] = []
    skipped_duplicates = 0
    seen_event_ids = set()

    for log in normalized_logs:
        event_id = str(log.get("event_id"))
        if event_id in seen_event_ids:
            skipped_duplicates += 1
            continue
        seen_event_ids.add(event_id)
        if event_id in existing_event_ids:
            skipped_duplicates += 1
            continue

        fields_value = log.get("fields") or {}
        fields_json = json.dumps(fields_value) if not isinstance(fields_value, str) else fields_value
        timestamp = parse_timestamp(str(log.get("timestamp"))) or datetime.now(timezone.utc)

        to_insert.append(
            EndpointLog(
                event_id=event_id,
                timestamp=timestamp,
                agent_id=str(log.get("agent_id")),
                hostname=log.get("hostname"),
                log_source=log.get("log_source"),
                event_type=log.get("event_type"),
                severity_raw=log.get("severity_raw"),
                raw=log.get("raw"),
                fields_json=fields_json
            )
        )

    ingest_ts = defaults.get("timestamp") or datetime.now(timezone.utc).isoformat()
    processed_result = process_logs_batch(
        defaults.get("agent_id") or "unknown",
        defaults.get("hostname") or "unknown",
        ingest_ts,
        normalized_logs
    )
    processed_batch = processed_result.get("processed", [])
    skipped_invalid += int(processed_result.get("skipped_invalid") or 0)

    fingerprints = []
    seen_fingerprints = set()
    unique_processed: List[Dict[str, Any]] = []
    for log in processed_batch:
        fingerprint = log.get("fingerprint")
        if not fingerprint:
            seed = f"{log.get('event_id')}|{log.get('timestamp')}"
            fingerprint = hashlib.sha256(seed.encode("utf-8")).hexdigest()
            log["fingerprint"] = fingerprint
        if fingerprint in seen_fingerprints:
            skipped_duplicates += 1
            continue
        seen_fingerprints.add(fingerprint)
        fingerprints.append(fingerprint)
        unique_processed.append(log)
    existing_fingerprints = set()
    if fingerprints:
        existing = db.query(ProcessedLog.fingerprint).filter(ProcessedLog.fingerprint.in_(fingerprints)).all()
        existing_fingerprints = {row[0] for row in existing}

    processed_to_insert: List[ProcessedLog] = []
    for log in unique_processed:
        fingerprint = log.get("fingerprint")
        if not fingerprint:
            continue
        if fingerprint in existing_fingerprints:
            skipped_duplicates += 1
            continue

        fields_payload = log.get("fields") or {}
        if not isinstance(fields_payload, dict):
            fields_payload = {}
        fields_payload["mitre_matches"] = log.get("mitre_matches") or []
        fields_payload["ioc_intel"] = log.get("ioc_intel") or {}
        fields_payload["severity_raw"] = log.get("severity_raw")
        fields_json = json.dumps(fields_payload)
        iocs_json = json.dumps(log.get("iocs") or {})
        tags_json = json.dumps(log.get("tags") or [])
        ts_value = parse_timestamp(str(log.get("timestamp"))) or parse_timestamp(str(ingest_ts)) or datetime.now(timezone.utc)

        processed_to_insert.append(
            ProcessedLog(
                agent_id=str(log.get("agent_id") or defaults.get("agent_id") or "unknown"),
                hostname=log.get("hostname") or defaults.get("hostname"),
                timestamp=ts_value,
                category=str(log.get("category") or "other"),
                event_type=str(log.get("event_type") or "other"),
                severity_score=int(log.get("severity_score") or 0),
                message=log.get("message") or "",
                raw=log.get("raw") or "",
                fields_json=fields_json,
                iocs_json=iocs_json,
                tags_json=tags_json,
                fingerprint=fingerprint
            )
        )

    raw_result = _safe_insert(db, to_insert)
    processed_result = _safe_insert(db, processed_to_insert)
    skipped_duplicates += raw_result["skipped"] + processed_result["skipped"]

    logger.info(
        "[INGEST] received=%s stored=%s processed=%s skipped_duplicates=%s skipped_invalid=%s",
        received,
        raw_result["stored"],
        processed_result["stored"],
        skipped_duplicates,
        skipped_invalid
    )

    if raw_result["stored"] == 0 and processed_result["stored"] == 0:
        raise HTTPException(status_code=409, detail="No logs stored (duplicates or invalid payload)")

    processed_ids: List[int] = []
    if processed_to_insert:
        fingerprints = [p.fingerprint for p in processed_to_insert if p.fingerprint]
        if fingerprints:
            rows = db.query(ProcessedLog.id).filter(ProcessedLog.fingerprint.in_(fingerprints)).all()
            processed_ids = [row[0] for row in rows]
    if processed_ids or processed_result["stored"] > 0:
        background_tasks.add_task(_run_post_ingest_pipeline, processed_ids)

    if settings.AI_LOG_NOTES_MODE and processed_to_insert:
        fingerprints = [p.fingerprint for p in processed_to_insert if p.fingerprint]
        if fingerprints:
            rows = db.query(ProcessedLog).filter(ProcessedLog.fingerprint.in_(fingerprints)).all()
            for row in rows:
                background_tasks.add_task(run_log_notes_task, row.id)

    return LogIngestResponse(
        status="ok",
        received=received,
        processed=processed_result["stored"],
        stored=raw_result["stored"],
        skipped_duplicates=skipped_duplicates,
        skipped_invalid=skipped_invalid
    )


@router.get("/logs/recent", response_model=List[LogRecord])
def get_recent_logs(
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    logs = (
        db.query(EndpointLog)
        .order_by(EndpointLog.timestamp.desc(), EndpointLog.created_at.desc())
        .limit(limit)
        .all()
    )

    results: List[LogRecord] = []
    for log in logs:
        fields_obj: Dict[str, Any] = {}
        if log.fields_json:
            try:
                fields_obj = json.loads(log.fields_json)
            except Exception:
                fields_obj = {}

        results.append(
            LogRecord(
                event_id=log.event_id,
                timestamp=log.timestamp.isoformat() if log.timestamp else None,
                agent_id=log.agent_id,
                hostname=log.hostname,
                log_source=log.log_source,
                event_type=log.event_type,
                severity_raw=log.severity_raw,
                raw=log.raw,
                fields=fields_obj
            )
        )

    return results


@router.get("/logs/processed/recent", response_model=List[ProcessedLogRecord])
def get_recent_processed_logs(
    limit: int = Query(50, ge=1, le=500),
    include_ai: bool = Query(False),
    db: Session = Depends(get_db)
):
    logs = (
        db.query(ProcessedLog)
        .order_by(ProcessedLog.timestamp.desc(), ProcessedLog.created_at.desc())
        .limit(limit)
        .all()
    )

    results: List[ProcessedLogRecord] = []
    for log in logs:
        fields_obj: Dict[str, Any] = _parse_json(log.fields_json, {})
        iocs_obj: Dict[str, Any] = _parse_json(log.iocs_json, {})
        tags_obj: List[str] = _parse_json(log.tags_json, [])
        mitre_matches = fields_obj.get("mitre_matches") or []
        ioc_intel = fields_obj.get("ioc_intel") or {}
        ai_notes = fields_obj.get("ai_notes") if include_ai else None

        results.append(
            ProcessedLogRecord(
                id=log.id,
                agent_id=log.agent_id,
                hostname=log.hostname,
                timestamp=log.timestamp.isoformat() if log.timestamp else None,
                category=log.category,
                event_type=log.event_type,
                severity_score=log.severity_score,
                message=log.message,
                raw=log.raw,
                fields_json=fields_obj,
                iocs_json=iocs_obj,
                tags_json=tags_obj,
                fingerprint=log.fingerprint,
                created_at=log.created_at.isoformat() if log.created_at else None,
                mitre_matches=mitre_matches if isinstance(mitre_matches, list) else [],
                ioc_intel=ioc_intel if isinstance(ioc_intel, dict) else {},
                ai_notes=ai_notes if isinstance(ai_notes, dict) else None
            )
        )

    return results


@router.get("/logs/processed/{processed_id}", response_model=ProcessedLogRecord)
def get_processed_log(processed_id: int, db: Session = Depends(get_db)):
    log = db.query(ProcessedLog).filter(ProcessedLog.id == processed_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Processed log not found")

    fields_obj: Dict[str, Any] = _parse_json(log.fields_json, {})
    iocs_obj: Dict[str, Any] = _parse_json(log.iocs_json, {})
    tags_obj: List[str] = _parse_json(log.tags_json, [])
    mitre_matches = fields_obj.get("mitre_matches") or []
    ioc_intel = fields_obj.get("ioc_intel") or {}
    ai_notes = fields_obj.get("ai_notes")

    return ProcessedLogRecord(
        id=log.id,
        agent_id=log.agent_id,
        hostname=log.hostname,
        timestamp=log.timestamp.isoformat() if log.timestamp else None,
        category=log.category,
        event_type=log.event_type,
        severity_score=log.severity_score,
        message=log.message,
        raw=log.raw,
        fields_json=fields_obj,
        iocs_json=iocs_obj,
        tags_json=tags_obj,
        fingerprint=log.fingerprint,
        created_at=log.created_at.isoformat() if log.created_at else None,
        mitre_matches=mitre_matches if isinstance(mitre_matches, list) else [],
        ioc_intel=ioc_intel if isinstance(ioc_intel, dict) else {},
        ai_notes=ai_notes if isinstance(ai_notes, dict) else None
    )
