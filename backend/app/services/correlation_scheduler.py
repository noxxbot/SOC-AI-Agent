import asyncio
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.database.db import SessionLocal
from app.models.models import ProcessedLog
from app.models.correlation_finding import CorrelationFinding
from app.services.ai_service import AIService
from app.services.correlation_engine import correlate_events


_started = False
logger = logging.getLogger(__name__)


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            normalized = value.replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def _normalize_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            normalized = value.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def _load_events(max_events: int, window_minutes: int) -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        logs = (
            db.query(ProcessedLog)
            .order_by(ProcessedLog.timestamp.desc(), ProcessedLog.created_at.desc())
            .limit(max_events)
            .all()
        )
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        events = []
        for log in logs:
            ts = _normalize_timestamp(log.timestamp or log.created_at)
            if ts and ts < cutoff:
                continue
            fields = {}
            iocs = {}
            tags = []
            if log.fields_json:
                try:
                    fields = json.loads(log.fields_json)
                except Exception:
                    fields = {}
            if log.iocs_json:
                try:
                    iocs = json.loads(log.iocs_json)
                except Exception:
                    iocs = {}
            if log.tags_json:
                try:
                    tags = json.loads(log.tags_json)
                except Exception:
                    tags = []
            events.append(
                {
                    "id": log.id,
                    "agent_id": log.agent_id,
                    "hostname": log.hostname,
                    "timestamp": (ts or datetime.now(timezone.utc)).isoformat(),
                    "category": log.category,
                    "event_type": log.event_type,
                    "severity_score": log.severity_score,
                    "message": log.message,
                    "raw": log.raw,
                    "fields": fields,
                    "iocs": iocs,
                    "tags": tags,
                    "fingerprint": log.fingerprint,
                    "mitre_matches": fields.get("mitre_matches", []),
                    "ioc_intel": fields.get("ioc_intel", {})
                }
            )
        return events
    finally:
        db.close()


def _store_findings(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        return
    db = SessionLocal()
    try:
        fingerprints = [f.get("fingerprint") for f in findings if f.get("fingerprint")]
        existing = set()
        if fingerprints:
            rows = db.query(CorrelationFinding.fingerprint).filter(CorrelationFinding.fingerprint.in_(fingerprints)).all()
            existing = {r[0] for r in rows}

        to_insert: List[CorrelationFinding] = []
        ai_service = AIService()
        for f in findings:
            fingerprint = f.get("fingerprint")
            if not fingerprint or fingerprint in existing:
                continue
            _attach_ai_notes_to_finding(f, ai_service)
            time_range = f.get("time_range") or {}
            to_insert.append(
                CorrelationFinding(
                    window_start=_parse_timestamp(time_range.get("start")),
                    window_end=_parse_timestamp(time_range.get("end")),
                    title=f.get("title") or "Correlation Finding",
                    severity=f.get("severity") or "medium",
                    confidence_score=int(f.get("confidence_score") or 0),
                    entities_json=json.dumps(f.get("entities") or {}),
                    evidence_json=json.dumps(f.get("evidence") or []),
                    mitre_json=json.dumps(f.get("mitre_summary") or []),
                    ioc_json=json.dumps(f.get("ioc_summary") or {}),
                    summary_text=f.get("title") or "",
                    status="open",
                    fingerprint=fingerprint
                )
            )
        if to_insert:
            try:
                db.add_all(to_insert)
                db.commit()
            except IntegrityError:
                db.rollback()
    finally:
        db.close()


def _severity_to_score(value: Any) -> int:
    sev = str(value or "").strip().lower()
    if sev == "critical":
        return 90
    if sev == "high":
        return 80
    if sev == "medium":
        return 60
    if sev == "low":
        return 30
    return 20


def _should_auto_notes_for_finding(finding: Dict[str, Any]) -> bool:
    mode = str(settings.AI_LOG_NOTES_MODE or "suspicious_only").strip().lower()
    if mode == "manual":
        return False
    if mode == "all":
        return True
    ioc_summary = finding.get("ioc_summary") or {}
    ioc_risk = str(ioc_summary.get("risk") or "").lower()
    mitre_summary = finding.get("mitre_summary") or []
    severity_score = _severity_to_score(finding.get("severity"))
    return severity_score >= 60 or bool(mitre_summary) or ioc_risk in {"suspicious", "malicious"}


def _attach_ai_notes_to_finding(finding: Dict[str, Any], ai_service: AIService) -> None:
    if not _should_auto_notes_for_finding(finding):
        return
    ioc_summary = finding.get("ioc_summary") or {}
    if isinstance(ioc_summary, dict) and ioc_summary.get("ai_notes"):
        return
    entities = finding.get("entities") or {}
    payload = {
        "timestamp": (finding.get("time_range") or {}).get("end"),
        "agent_id": entities.get("agent_id") or entities.get("agent"),
        "hostname": entities.get("hostname"),
        "category": "correlation",
        "event_type": finding.get("title") or "Correlation Finding",
        "severity_score": _severity_to_score(finding.get("severity")),
        "message": finding.get("title") or "",
        "raw": json.dumps(finding, default=str),
        "fields": {
            "mitre_matches": finding.get("mitre_summary") or [],
            "ioc_intel": {"ioc_summary": ioc_summary, "ioc_matches": []}
        },
        "iocs": {},
        "tags": ["correlation", f"rule:{finding.get('rule_name') or 'unknown'}"]
    }
    try:
        notes = asyncio.run(ai_service.generate_log_notes(payload))
    except Exception:
        logger.exception("correlation ai notes failed", extra={"fingerprint": finding.get("fingerprint")})
        notes = {"error": "LLM unavailable"}
    if not isinstance(ioc_summary, dict):
        ioc_summary = {}
    ioc_summary["ai_notes"] = notes
    finding["ioc_summary"] = ioc_summary


def run_correlation_once() -> Dict[str, Any]:
    window_minutes = int(os.getenv("CORRELATION_WINDOW_MINUTES", "15"))
    max_events = int(os.getenv("CORRELATION_MAX_EVENTS", "500"))
    events = _load_events(max_events, window_minutes)
    output = correlate_events(events, window_minutes)
    _store_findings(output.get("correlation_findings", []))
    return output


def _loop(interval_seconds: int) -> None:
    while True:
        try:
            run_correlation_once()
        except Exception:
            pass
        time.sleep(interval_seconds)


def start_scheduler() -> None:
    global _started
    if _started:
        return
    interval = int(os.getenv("CORRELATION_INTERVAL_SECONDS", "60"))
    thread = threading.Thread(target=_loop, args=(interval,), daemon=True)
    thread.start()
    _started = True
