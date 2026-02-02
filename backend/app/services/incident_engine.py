import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.db import SessionLocal
from app.models.ai_investigation import AIInvestigation
from app.models.correlation_finding import CorrelationFinding
from app.models.detection_alert import DetectionAlert
from app.models.incident import Incident
from app.models.models import ProcessedLog

logger = logging.getLogger(__name__)


def _parse_json(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _severity_rank(value: Optional[str]) -> int:
    sev = str(value or "").strip().lower()
    mapping = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping.get(sev, 1)


def _normalize_severity(value: Optional[str]) -> str:
    sev = str(value or "").strip().lower()
    return sev or "low"


def _bucket_time(ts: datetime, bucket_seconds: int) -> str:
    epoch = int(ts.timestamp())
    bucket = epoch - (epoch % max(1, bucket_seconds))
    return datetime.fromtimestamp(bucket, tz=timezone.utc).isoformat()


def _serialize_processed_log(log: ProcessedLog) -> Dict[str, Any]:
    ts = _ensure_utc(log.timestamp)
    return {
        "id": log.id,
        "timestamp": ts.isoformat() if ts else None,
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
        center = _ensure_utc(alert.created_at) or datetime.now(timezone.utc)
        start = center - timedelta(seconds=window_seconds)
        end = center + timedelta(seconds=window_seconds)
        query = db.query(ProcessedLog).filter(ProcessedLog.timestamp >= start, ProcessedLog.timestamp <= end)
        if alert.agent_id:
            query = query.filter(ProcessedLog.agent_id == alert.agent_id)
        related_logs = query.order_by(ProcessedLog.timestamp.desc()).limit(100).all()

    unique_logs: Dict[int, ProcessedLog] = {log.id: log for log in related_logs}
    processed_logs = [_serialize_processed_log(log) for log in unique_logs.values()]

    window_seconds = int(os.getenv("RULE_WINDOW_SECONDS", "600"))
    center = _ensure_utc(alert.created_at) or datetime.now(timezone.utc)
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

    ai_row = (
        db.query(AIInvestigation)
        .filter(AIInvestigation.alert_id == alert.id)
        .order_by(AIInvestigation.created_at.desc())
        .first()
    )
    ai_investigation = None
    if ai_row:
        created_at = _ensure_utc(ai_row.created_at)
        ai_investigation = {
            "id": ai_row.id,
            "created_at": created_at.isoformat() if created_at else None,
            "status": ai_row.status,
            "investigation": _parse_json(ai_row.investigation_json, {}),
            "confidence_score": ai_row.confidence_score,
            "is_incident": bool(ai_row.is_incident),
            "incident_severity": ai_row.incident_severity
        }

    return {
        "processed_logs": processed_logs,
        "correlation_findings": correlation_findings,
        "ai_investigation": ai_investigation,
        "evidence": evidence
    }


def decide_incident(alert: DetectionAlert, context: Dict[str, Any]) -> Dict[str, Any]:
    context = context or {}
    reasons: List[str] = []
    sources: List[str] = []
    should_create = False

    alert_sev = _normalize_severity(alert.severity)
    if alert_sev == "info":
        return {
            "should_create": False,
            "severity": alert_sev,
            "confidence_score": 0,
            "reason": "Informational alert",
            "source": "rule_engine",
            "title": f"Incident: {alert.rule_name}",
            "summary": alert.summary or "",
            "fingerprint": ""
        }

    processed_logs = context.get("processed_logs") or []
    correlation_findings = context.get("correlation_findings") or []
    ai_investigation = context.get("ai_investigation") or {}
    evidence = context.get("evidence") or {}

    min_severity = _normalize_severity(settings.INCIDENT_MIN_SEVERITY)
    min_rank = _severity_rank(min_severity)
    alert_rank = _severity_rank(alert_sev)

    max_log_severity = 0
    log_fingerprints: List[str] = []
    ioc_matches: List[Dict[str, Any]] = []
    ioc_summaries: List[Dict[str, Any]] = []
    mitre_matches: List[Dict[str, Any]] = []
    agent_id = None
    hostname = None

    for log in processed_logs:
        max_log_severity = max(max_log_severity, int(log.get("severity_score") or 0))
        if log.get("fingerprint"):
            log_fingerprints.append(log.get("fingerprint"))
        fields = log.get("fields") or {}
        ioc_intel = fields.get("ioc_intel") or log.get("ioc_intel") or {}
        summary = ioc_intel.get("ioc_summary") or {}
        matches = ioc_intel.get("ioc_matches") or []
        if summary:
            ioc_summaries.append(summary)
        if matches:
            ioc_matches.extend(matches)
        mitre = fields.get("mitre_matches") or log.get("mitre_matches") or []
        if mitre:
            mitre_matches.extend(mitre)
        if not agent_id:
            agent_id = log.get("agent_id")
        if not hostname:
            hostname = log.get("hostname")

    if not agent_id:
        agent_id = evidence.get("agent_id")
    if not hostname:
        hostname = evidence.get("hostname")

    alert_ioc_matches = _parse_json(alert.ioc_json, [])
    if alert_ioc_matches:
        ioc_matches.extend(alert_ioc_matches)

    alert_mitre_matches = _parse_json(alert.mitre_json, [])
    if alert_mitre_matches:
        mitre_matches.extend(alert_mitre_matches)

    severity_score_threshold = 70
    rule_trigger = False
    if alert_sev in {"high", "critical"} or max_log_severity >= severity_score_threshold:
        if alert_rank >= min_rank or alert_sev in {"high", "critical"}:
            should_create = True
            rule_trigger = True
            sources.append("rule_engine")
            reasons.append("High severity alert or elevated severity score")

    correlation_trigger = False
    multi_stage_signals = {"brute_force_success", "powershell_network_chain", "lateral_movement"}
    for finding in correlation_findings:
        rule_name = str(finding.get("rule_name") or "")
        title = str(finding.get("title") or "").lower()
        confidence = int(finding.get("confidence_score") or 0)
        evidence = finding.get("evidence") or []
        if rule_name in multi_stage_signals or "followed" in title or "chain" in title:
            if confidence >= 60 or len(evidence) >= 2:
                correlation_trigger = True
                break
    if correlation_trigger:
        should_create = True
        sources.append("correlation_engine")
        reasons.append("Correlation indicates multi-stage activity")

    ioc_trigger = False
    primary_iocs: List[Dict[str, Any]] = []
    for summary in ioc_summaries:
        risk = str(summary.get("risk") or "").lower()
        confidence = int(summary.get("confidence") or 0)
        if risk in {"malicious", "suspicious"} and confidence >= 60:
            ioc_trigger = True
            break
    if ioc_trigger:
        should_create = True
        sources.append("rule_engine")
        reasons.append("IOC intel indicates malicious or suspicious activity")

    for match in ioc_matches:
        verdict = str(match.get("verdict") or "").lower()
        if verdict in {"malicious", "suspicious"}:
            primary_iocs.append(match)
    if not primary_iocs and ioc_matches:
        primary_iocs = ioc_matches[:3]

    mitre_trigger = False
    high_signal_tactics = {"execution", "persistence", "credential-access", "lateral-movement"}
    primary_techniques: List[Dict[str, Any]] = []
    for match in mitre_matches:
        confidence = int(match.get("confidence_score") or 0)
        tactics = match.get("tactics") or []
        tactics = [str(t).strip().lower() for t in tactics if str(t).strip()]
        if confidence >= 70 and any(t in high_signal_tactics for t in tactics):
            mitre_trigger = True
            primary_techniques.append(match)
    if mitre_trigger:
        should_create = True
        sources.append("rule_engine")
        reasons.append("High-confidence MITRE technique in high-signal tactics")

    ai_trigger = False
    ai_payload = ai_investigation.get("investigation") or {}
    ai_risk_score = ai_payload.get("risk_score")
    ai_confidence = int(ai_payload.get("confidence_score") or ai_investigation.get("confidence_score") or 0)
    ai_is_incident = bool(ai_payload.get("is_incident") or ai_investigation.get("is_incident"))
    if ai_is_incident or ai_confidence >= 70:
        ai_trigger = True
    if ai_risk_score is not None:
        try:
            if int(ai_risk_score) >= 75:
                ai_trigger = True
        except Exception:
            pass
    if ai_trigger:
        should_create = True
        sources.append("ai_engine")
        reasons.append("AI investigation indicates incident risk")

    benign_only = False
    if ioc_matches and not ioc_trigger:
        benign_verdicts = [str(m.get("verdict") or "").lower() for m in ioc_matches]
        if all(v == "benign" for v in benign_verdicts):
            benign_only = True

    if benign_only and not (rule_trigger or correlation_trigger or mitre_trigger or ai_trigger):
        should_create = False
        reasons = ["Only benign allowlisted IOC matched"]

    if correlation_findings and not (rule_trigger or ioc_trigger or mitre_trigger or ai_trigger):
        max_conf = max([int(f.get("confidence_score") or 0) for f in correlation_findings], default=0)
        if len(correlation_findings) == 1 and max_conf < 50:
            should_create = False
            reasons = ["Low confidence isolated correlation finding"]

    source = "mixed"
    if not sources:
        source = "rule_engine"
    elif len(set(sources)) == 1:
        source = sources[0]

    confidence_score = 0
    if should_create:
        confidence_score = 60
        if rule_trigger:
            confidence_score = max(confidence_score, 70)
        if correlation_trigger:
            confidence_score = max(confidence_score, 80)
        if ioc_trigger:
            confidence_score = max(confidence_score, 85)
        if mitre_trigger:
            confidence_score = max(confidence_score, 75)
        if ai_trigger:
            confidence_score = max(confidence_score, max(80, ai_confidence))
        confidence_score = int(max(0, min(100, confidence_score)))

    decision_severity = alert_sev
    if ai_trigger and ai_investigation.get("incident_severity"):
        ai_severity = _normalize_severity(ai_investigation.get("incident_severity"))
        if _severity_rank(ai_severity) > _severity_rank(decision_severity):
            decision_severity = ai_severity
    elif ioc_trigger or correlation_trigger or mitre_trigger:
        decision_severity = "high" if _severity_rank(alert_sev) < 3 else alert_sev

    reason_text = " + ".join(reasons) if reasons else "No escalation conditions met"

    primary_technique_id = ""
    if primary_techniques:
        primary_technique_id = str(primary_techniques[0].get("technique_id") or primary_techniques[0].get("id") or "")
    primary_ioc_value = ""
    if primary_iocs:
        primary_ioc_value = str(primary_iocs[0].get("ioc") or "")

    dedup_window = int(settings.INCIDENT_DEDUP_WINDOW_SECONDS)
    base_ts = alert.created_at or datetime.now(timezone.utc)
    bucket = _bucket_time(base_ts, dedup_window)
    fingerprint_payload = "|".join([
        str(agent_id or ""),
        str(hostname or ""),
        primary_technique_id,
        primary_ioc_value,
        str(alert.rule_id or ""),
        bucket
    ])
    fingerprint = hashlib.sha256(fingerprint_payload.encode("utf-8")).hexdigest()

    return {
        "should_create": bool(should_create),
        "severity": decision_severity,
        "confidence_score": confidence_score,
        "reason": reason_text,
        "source": source,
        "title": f"Incident: {alert.rule_name}",
        "summary": alert.summary or reason_text,
        "fingerprint": fingerprint,
        "primary_iocs": primary_iocs,
        "primary_techniques": primary_techniques,
        "related_log_fingerprints": log_fingerprints,
        "agent_id": agent_id,
        "hostname": hostname
    }


def create_or_link_incident(
    db: Session,
    decision: Dict[str, Any],
    alert: DetectionAlert
) -> Optional[Incident]:
    if not decision.get("should_create"):
        return None

    fingerprint = decision.get("fingerprint")
    if not fingerprint:
        return None

    window_seconds = int(settings.INCIDENT_DEDUP_WINDOW_SECONDS)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    existing = (
        db.query(Incident)
        .filter(Incident.incident_fingerprint == fingerprint, Incident.created_at >= cutoff)
        .order_by(Incident.created_at.desc())
        .first()
    )

    if existing:
        alert_ids = _parse_json(existing.related_alert_ids_json, [])
        if alert.id not in alert_ids:
            alert_ids.append(alert.id)
        log_fps = _parse_json(existing.related_log_fingerprints_json, [])
        for fp in decision.get("related_log_fingerprints") or []:
            if fp not in log_fps:
                log_fps.append(fp)
        existing.related_alert_ids_json = json.dumps(alert_ids)
        existing.related_log_fingerprints_json = json.dumps(log_fps)
        existing.updated_at = datetime.now(timezone.utc)
        try:
            db.add(existing)
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("incident link failed", extra={"alert_id": alert.id, "fingerprint": fingerprint})
        return existing

    confidence_value = int(alert.confidence_score or decision.get("confidence_score") or 0)
    incident = Incident(
        title=decision.get("title") or "Incident",
        summary=decision.get("summary") or "",
        severity=decision.get("severity") or "low",
        confidence_score=confidence_value,
        incident_fingerprint=fingerprint,
        source=decision.get("source") or "rule_engine",
        agent_id=decision.get("agent_id"),
        hostname=decision.get("hostname"),
        primary_iocs_json=json.dumps(decision.get("primary_iocs") or []),
        mitre_techniques_json=json.dumps(decision.get("primary_techniques") or []),
        related_alert_ids_json=json.dumps([alert.id]),
        related_log_fingerprints_json=json.dumps(decision.get("related_log_fingerprints") or []),
        decision_reason=decision.get("reason") or ""
    )

    try:
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(Incident)
            .filter(Incident.incident_fingerprint == fingerprint)
            .order_by(Incident.created_at.desc())
            .first()
        )
        if existing:
            return existing
        return None
    except Exception:
        db.rollback()
        logger.exception("incident create failed", extra={"alert_id": alert.id, "fingerprint": fingerprint})
        return None


async def run_incident_task(alert_id: int) -> None:
    db = SessionLocal()
    try:
        alert = db.query(DetectionAlert).filter(DetectionAlert.id == alert_id).first()
        if not alert:
            return
        ai_row = (
            db.query(AIInvestigation)
            .filter(AIInvestigation.alert_id == alert.id)
            .order_by(AIInvestigation.created_at.desc())
            .first()
        )
        threshold = int(getattr(settings, "INCIDENT_AI_MIN_CONFIDENCE", 60) or 60)
        if (
            not ai_row
            or ai_row.status != "completed"
            or not ai_row.is_incident
            or int(ai_row.confidence_score or 0) < threshold
        ):
            logger.info(
                "incident skipped (ai gating)",
                extra={
                    "alert_id": alert_id,
                    "status": ai_row.status if ai_row else None,
                    "is_incident": ai_row.is_incident if ai_row else None,
                    "confidence_score": ai_row.confidence_score if ai_row else None,
                    "threshold": threshold
                }
            )
            return
        context = _build_context(db, alert)
        decision = decide_incident(alert, context)
        decision["should_create"] = True
        decision["confidence_score"] = max(int(decision.get("confidence_score") or 0), int(ai_row.confidence_score or 0))
        decision["source"] = "ai_investigation"
        decision["reason"] = "AI investigation confirmed incident"
        decision["summary"] = alert.summary or decision.get("summary") or "AI investigation confirmed incident"
        decision["severity"] = ai_row.incident_severity or decision.get("severity") or "low"
        create_or_link_incident(db, decision, alert)
    except Exception:
        logger.exception("incident task error", extra={"alert_id": alert_id})
    finally:
        db.close()


def build_incident_context(db: Session, alert: DetectionAlert) -> Dict[str, Any]:
    return _build_context(db, alert)
