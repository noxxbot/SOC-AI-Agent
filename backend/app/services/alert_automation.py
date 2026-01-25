import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.db import SessionLocal
from app.models.ai_investigation import AIInvestigation
from app.models.correlation_finding import CorrelationFinding
from app.models.detection_alert import DetectionAlert
from app.models.models import ProcessedLog
from app.services.ai_service import AIService
from app.services.incident_engine import build_incident_context, decide_incident, create_or_link_incident

logger = logging.getLogger(__name__)
ai_service = AIService()


def _parse_json(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _default_investigation_payload() -> Dict[str, Any]:
    return {
        "summary": "AI investigation unavailable.",
        "case_notes": "AI investigation unavailable.",
        "explainability": [
            "AI output was unavailable for this investigation.",
            "No additional evidence could be evaluated.",
            "Investigation requires manual review.",
            "Additional telemetry is needed for validation."
        ],
        "assessment": {
            "is_incident": False,
            "incident_severity": "none",
            "confidence_score": 0,
            "reasoning": "AI output was unavailable; manual review required."
        },
        "recommended_actions": [
            "Review alert evidence manually.",
            "Collect additional telemetry for validation.",
            "Monitor for related activity."
        ],
        "ioc_analysis": {
            "observed_iocs": [],
            "ioc_verdict": "unknown",
            "ioc_notes": "No IOC analysis available."
        },
        "mitre_analysis": {
            "techniques": [],
            "tactics": [],
            "mitre_notes": "No MITRE analysis available."
        },
        "timeline": [
            "Step 1: Alert triggered and AI investigation started.",
            "Step 2: AI output unavailable for analysis.",
            "Step 3: Manual investigation recommended."
        ],
        "mitre_mapping": [],
        "ioc_verdicts": [],
        "confidence_score": 0,
        "is_incident": False,
        "incident_severity": "none",
        "confidence_breakdown": {}
    }


def _serialize_processed_log(log: ProcessedLog) -> Dict[str, Any]:
    return {
        "id": log.id,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        "agent_id": log.agent_id,
        "hostname": log.hostname,
        "category": log.category,
        "event_type": log.event_type,
        "severity_score": log.severity_score,
        "message": log.message,
        "raw": log.raw,
        "fields": _parse_json(log.fields_json, {}),
        "iocs": _parse_json(log.iocs_json, {}),
        "tags": _parse_json(log.tags_json, []),
        "fingerprint": log.fingerprint
    }


def _serialize_finding(finding: CorrelationFinding) -> Dict[str, Any]:
    return {
        "id": finding.id,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
        "window_start": finding.window_start.isoformat() if finding.window_start else None,
        "window_end": finding.window_end.isoformat() if finding.window_end else None,
        "title": finding.title,
        "severity": finding.severity,
        "confidence_score": finding.confidence_score,
        "entities": _parse_json(finding.entities_json, {}),
        "evidence": _parse_json(finding.evidence_json, []),
        "mitre_summary": _parse_json(finding.mitre_json, []),
        "ioc_summary": _parse_json(finding.ioc_json, {}),
        "summary_text": finding.summary_text,
        "status": finding.status,
        "fingerprint": finding.fingerprint
    }


def _build_alert_payload(alert: DetectionAlert) -> Dict[str, Any]:
    evidence = _parse_json(alert.evidence_json, {})
    return {
        "id": alert.id,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "confidence_score": alert.confidence_score,
        "category": alert.category,
        "status": alert.status,
        "summary": alert.summary,
        "evidence": evidence,
        "mitre": _parse_json(alert.mitre_json, []),
        "ioc_matches": _parse_json(alert.ioc_json, []),
        "recommended_actions": _parse_json(alert.actions_json, [])
    }


def _build_context(db: Session, alert: DetectionAlert) -> Dict[str, Any]:
    evidence = _parse_json(alert.evidence_json, {})
    processed_ids = evidence.get("processed_ids") or []
    fingerprints = evidence.get("fingerprints") or []

    related_logs: List[ProcessedLog] = []
    if processed_ids:
        related_logs.extend(
            db.query(ProcessedLog).filter(ProcessedLog.id.in_(processed_ids)).all()
        )
    if fingerprints:
        related_logs.extend(
            db.query(ProcessedLog).filter(ProcessedLog.fingerprint.in_(fingerprints)).all()
        )

    if not related_logs:
        window_seconds = int(os.getenv("RULE_WINDOW_SECONDS", "600"))
        center = alert.created_at or datetime.now(timezone.utc)
        start = center - timedelta(seconds=window_seconds)
        end = center + timedelta(seconds=window_seconds)
        related_logs = (
            db.query(ProcessedLog)
            .filter(ProcessedLog.timestamp >= start, ProcessedLog.timestamp <= end)
            .order_by(ProcessedLog.timestamp.desc())
            .limit(50)
            .all()
        )

    unique_logs: Dict[int, ProcessedLog] = {log.id: log for log in related_logs}
    processed_logs = [_serialize_processed_log(log) for log in unique_logs.values()]

    window_seconds = int(os.getenv("RULE_WINDOW_SECONDS", "600"))
    center = alert.created_at or datetime.now(timezone.utc)
    start = center - timedelta(seconds=window_seconds)
    end = center + timedelta(seconds=window_seconds)
    findings = (
        db.query(CorrelationFinding)
        .filter(CorrelationFinding.created_at >= start, CorrelationFinding.created_at <= end)
        .order_by(CorrelationFinding.created_at.desc())
        .limit(50)
        .all()
    )
    correlation_findings = [_serialize_finding(f) for f in findings]

    return {
        "processed_logs": processed_logs,
        "correlation_findings": correlation_findings,
        "mitre_intel": _parse_json(alert.mitre_json, []),
        "ioc_intel": _parse_json(alert.ioc_json, []),
        "recommended_actions": _parse_json(alert.actions_json, []),
        "evidence": evidence
    }


def build_investigation_context(db: Session, alert: DetectionAlert) -> Dict[str, Any]:
    return _build_context(db, alert)


def _update_evidence(alert: DetectionAlert, updates: Dict[str, Any]) -> Dict[str, Any]:
    evidence = _parse_json(alert.evidence_json, {})
    evidence.update(updates)
    alert.evidence_json = json.dumps(evidence)
    return evidence


def _should_auto_investigate() -> bool:
    if not settings.AI_INVESTIGATE_ON_CREATE:
        return False
    mode = str(settings.AI_INVESTIGATE_MODE or "all").strip().lower()
    if mode == "manual":
        return False
    return True


def _build_ai_fingerprint(alert: DetectionAlert) -> str:
    seed = f"{alert.id}|{alert.rule_id}|{alert.created_at.isoformat() if alert.created_at else ''}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _ensure_ai_decision(alert: DetectionAlert, context: Dict[str, Any], investigation: AIInvestigation) -> Dict[str, Any]:
    decision = decide_incident(alert, build_incident_context(SessionLocal(), alert))
    if decision.get("should_create") and decision.get("fingerprint"):
        return decision
    evidence = context.get("evidence") or {}
    related_fps = []
    for log in context.get("processed_logs") or []:
        fp = log.get("fingerprint")
        if fp:
            related_fps.append(fp)
    return {
        "should_create": True,
        "severity": investigation.incident_severity or "low",
        "confidence_score": int(investigation.confidence_score or 0),
        "reason": "AI investigation flagged incident",
        "source": "ai_investigation",
        "title": f"Incident: {alert.rule_name}",
        "summary": alert.summary or "AI investigation flagged incident",
        "fingerprint": _build_ai_fingerprint(alert),
        "primary_iocs": [],
        "primary_techniques": [],
        "related_log_fingerprints": related_fps,
        "agent_id": evidence.get("agent_id"),
        "hostname": evidence.get("hostname")
    }


async def run_ai_investigation_and_maybe_create_incident(alert_id: int, force: bool = False) -> Optional[AIInvestigation]:
    db = SessionLocal()
    record: Optional[AIInvestigation] = None
    try:
        alert = db.query(DetectionAlert).filter(DetectionAlert.id == alert_id).first()
        if not alert:
            logger.warning("ai investigation alert missing", extra={"alert_id": alert_id})
            return None

        evidence = _parse_json(alert.evidence_json, {})
        if evidence.get("ai_status") == "completed" and not force:
            existing = (
                db.query(AIInvestigation)
                .filter(AIInvestigation.alert_id == alert.id)
                .order_by(AIInvestigation.created_at.desc())
                .first()
            )
            if existing:
                logger.info("ai investigation skipped (already completed)", extra={"alert_id": alert_id})
                return existing

        if not force:
            existing = (
                db.query(AIInvestigation)
                .filter(AIInvestigation.alert_id == alert.id)
                .order_by(AIInvestigation.created_at.desc())
                .first()
            )
            if existing:
                _update_evidence(alert, {"ai_status": "completed", "latest_investigation_id": existing.id})
                db.add(alert)
                db.commit()
                logger.info("ai investigation skipped (latest exists)", extra={"alert_id": alert_id})
                return existing

        _update_evidence(alert, {"ai_status": "running"})
        db.add(alert)
        db.commit()

        alert_payload = _build_alert_payload(alert)
        context = build_investigation_context(db, alert)
        prompt = ai_service.build_investigation_prompt(alert_payload, context)
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        if force:
            prompt_hash = hashlib.sha256(
                f"{prompt}|{datetime.now(timezone.utc).isoformat()}".encode("utf-8")
            ).hexdigest()

        record = AIInvestigation(
            alert_id=alert.id,
            model_name=ai_service.model,
            prompt_hash=prompt_hash,
            status="running"
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        try:
            ai_result = await ai_service.investigate_alert(alert_payload, context)
            result = ai_result.get("result") or {}
            raw_output = ai_result.get("raw_output") or ""
            record.investigation_json = json.dumps(result)
            record.investigation_text = raw_output
            record.confidence_score = int(result.get("confidence_score") or 0)
            status_flag = str(result.get("status") or "").lower()
            error_message = result.get("error_message")
            if status_flag == "failed" or error_message:
                record.status = "failed"
                record.is_incident = False
                record.incident_severity = "none"
                record.error_message = str(error_message) if error_message else "ai_investigation_failed"
            else:
                record.status = "completed"
                record.is_incident = bool(result.get("is_incident"))
                record.incident_severity = str(result.get("incident_severity") or "none")
                record.error_message = None
        except Exception as exc:
            record.investigation_json = json.dumps(_default_investigation_payload())
            record.investigation_text = ""
            record.confidence_score = 0
            record.is_incident = False
            record.incident_severity = "none"
            record.status = "failed"
            record.error_message = str(exc)
            logger.exception("ai investigation failed", extra={"alert_id": alert_id})

        db.add(record)
        db.commit()
        db.refresh(record)

        updates = {
            "ai_status": "completed" if record.status == "completed" else "failed",
            "latest_investigation_id": record.id
        }

        if record.status == "completed" and record.is_incident:
            decision = _ensure_ai_decision(alert, context, record)
            incident = create_or_link_incident(db, decision, alert)
            if incident:
                updates["incident_id"] = incident.id
                logger.info("incident created", extra={"alert_id": alert_id, "incident_id": incident.id})
            else:
                logger.info("incident skipped", extra={"alert_id": alert_id})
        else:
            logger.info("incident skipped (ai=false)", extra={"alert_id": alert_id})

        _update_evidence(alert, updates)
        db.add(alert)
        db.commit()
        return record
    except Exception as exc:
        alert = None
        try:
            alert = db.query(DetectionAlert).filter(DetectionAlert.id == alert_id).first()
        except Exception:
            db.rollback()
        if record:
            try:
                record.status = "failed"
                record.error_message = "automation failure"
                if not record.investigation_json:
                    record.investigation_json = json.dumps(_default_investigation_payload())
                if not record.incident_severity:
                    record.incident_severity = "none"
                db.add(record)
                db.commit()
            except Exception:
                db.rollback()
        elif alert:
            try:
                record = AIInvestigation(
                    alert_id=alert.id,
                    model_name=ai_service.model,
                    prompt_hash=_build_ai_fingerprint(alert),
                    investigation_json=json.dumps(_default_investigation_payload()),
                    investigation_text="",
                    confidence_score=0,
                    is_incident=False,
                    incident_severity="none",
                    status="failed",
                    error_message=str(exc)
                )
                db.add(record)
                db.commit()
                db.refresh(record)
            except Exception:
                db.rollback()
        if alert:
            try:
                updates = {"ai_status": "failed"}
                if record and record.id:
                    updates["latest_investigation_id"] = record.id
                _update_evidence(alert, updates)
                db.add(alert)
                db.commit()
            except Exception:
                db.rollback()
        logger.exception("ai automation failed", extra={"alert_id": alert_id})
        return record
    finally:
        db.close()


def run_ai_investigation_and_maybe_create_incident_task(alert_id: int, force: bool = False) -> None:
    try:
        asyncio.run(run_ai_investigation_and_maybe_create_incident(alert_id, force))
    except RuntimeError:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(run_ai_investigation_and_maybe_create_incident(alert_id, force))


def schedule_ai_investigation(
    alert_id: int,
    db: Session,
    background_tasks: BackgroundTasks,
    force: bool = False
) -> bool:
    if not force and not _should_auto_investigate():
        logger.info("ai auto disabled", extra={"alert_id": alert_id})
        return False
    alert = db.query(DetectionAlert).filter(DetectionAlert.id == alert_id).first()
    if not alert:
        logger.warning("alert missing for scheduling", extra={"alert_id": alert_id})
        return False
    if not force:
        existing = (
            db.query(AIInvestigation.id)
            .filter(
                AIInvestigation.alert_id == alert.id,
                AIInvestigation.status.in_(["completed", "failed", "running"])
            )
            .first()
        )
        if existing:
            logger.info("ai schedule skipped (already investigated)", extra={"alert_id": alert_id})
            return False
    evidence = _parse_json(alert.evidence_json, {})
    if evidence.get("ai_status") == "completed" and not force:
        logger.info("ai schedule skipped (completed)", extra={"alert_id": alert_id})
        return False
    _update_evidence(alert, {"ai_status": "pending"})
    db.add(alert)
    db.commit()
    background_tasks.add_task(run_ai_investigation_and_maybe_create_incident_task, alert_id, force)
    logger.info("ai investigation scheduled", extra={"alert_id": alert_id})
    return True
