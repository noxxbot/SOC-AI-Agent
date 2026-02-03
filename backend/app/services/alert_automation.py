import asyncio
import hashlib
import json
import logging
import os
import re
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
from app.services.rule_engine import run_rule_engine
from app.services.notification_service import broadcast_sync

logger = logging.getLogger(__name__)
ai_service = AIService()


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


def _default_investigation_payload() -> Dict[str, Any]:
    return {
        "summary": "AI failed – manual review needed.",
        "case_notes": "AI failed – manual review needed.",
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
    created = _ensure_utc(finding.created_at)
    window_start = _ensure_utc(finding.window_start)
    window_end = _ensure_utc(finding.window_end)
    return {
        "id": finding.id,
        "created_at": created.isoformat() if created else None,
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
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


def _update_analysis(log: ProcessedLog, updates: Dict[str, Any]) -> Dict[str, Any]:
    fields = _parse_json(log.fields_json, {})
    if not isinstance(fields, dict):
        fields = {}
    analysis = fields.get("analysis")
    if not isinstance(analysis, dict):
        analysis = {}
    analysis.update(updates or {})
    fields["analysis"] = analysis
    log.fields_json = json.dumps(fields)
    return analysis


def mark_logs_analyzed(db: Session, processed_ids: List[int]) -> int:
    if not processed_ids:
        return 0
    logs = db.query(ProcessedLog).filter(ProcessedLog.id.in_(processed_ids)).all()
    now = datetime.now(timezone.utc).isoformat()
    for log in logs:
        _update_analysis(log, {"analyzed": True, "analyzed_at": now})
        db.add(log)
    db.commit()
    for log in logs:
        logger.info("log analyzed", extra={"processed_id": log.id})
    return len(logs)


def _mark_alert_on_logs(
    db: Session,
    processed_ids: List[int],
    fingerprints: List[str],
    alert_id: int
) -> int:
    targets: List[ProcessedLog] = []
    if processed_ids:
        targets.extend(db.query(ProcessedLog).filter(ProcessedLog.id.in_(processed_ids)).all())
    if fingerprints:
        targets.extend(db.query(ProcessedLog).filter(ProcessedLog.fingerprint.in_(fingerprints)).all())
    seen: Dict[int, ProcessedLog] = {log.id: log for log in targets}
    updated = 0
    for log in seen.values():
        analysis = _update_analysis(
            log,
            {
                "alert_created": True,
                "latest_alert_id": alert_id
            }
        )
        alert_ids = analysis.get("alert_ids")
        if not isinstance(alert_ids, list):
            alert_ids = []
        if alert_id not in alert_ids:
            alert_ids.append(alert_id)
        analysis["alert_ids"] = alert_ids
        fields = _parse_json(log.fields_json, {})
        if not isinstance(fields, dict):
            fields = {}
        fields["analysis"] = analysis
        log.fields_json = json.dumps(fields)
        db.add(log)
        updated += 1
    if updated:
        db.commit()
    return updated


def create_or_update_alert_from_analysis(
    db: Session,
    alert_payload: Dict[str, Any]
) -> Optional[DetectionAlert]:
    fingerprint = alert_payload.get("fingerprint")
    if not fingerprint:
        return None
    existing = db.query(DetectionAlert).filter(DetectionAlert.fingerprint == fingerprint).first()
    evidence = alert_payload.get("evidence") or {}
    if existing:
        existing.summary = alert_payload.get("summary") or existing.summary
        existing.evidence_json = json.dumps(evidence)
        if alert_payload.get("mitre") is not None:
            existing.mitre_json = json.dumps(alert_payload.get("mitre") or [])
        if alert_payload.get("ioc_matches") is not None:
            existing.ioc_json = json.dumps(alert_payload.get("ioc_matches") or [])
        if alert_payload.get("recommended_actions") is not None:
            existing.actions_json = json.dumps(alert_payload.get("recommended_actions") or [])
        db.add(existing)
        db.commit()
        db.refresh(existing)
        context = _build_context(db, existing)
        _apply_confidence(db, existing, context, context.get("ai_investigation") or {})
        return existing

    record = DetectionAlert(
        rule_id=alert_payload.get("rule_id") or "RULE-UNKNOWN",
        rule_name=alert_payload.get("rule_name") or "Unnamed Rule",
        severity=alert_payload.get("severity") or "medium",
        confidence_score=int(alert_payload.get("confidence_score") or 0),
        category=alert_payload.get("category") or "general",
        status=alert_payload.get("status") or "open",
        summary=alert_payload.get("summary") or evidence.get("summary"),
        evidence_json=json.dumps(evidence),
        mitre_json=json.dumps(alert_payload.get("mitre") or []),
        ioc_json=json.dumps(alert_payload.get("ioc_matches") or []),
        actions_json=json.dumps(alert_payload.get("recommended_actions") or []),
        fingerprint=fingerprint
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    context = _build_context(db, record)
    _apply_confidence(db, record, context, context.get("ai_investigation") or {})
    return record


def run_detection_pipeline_task(processed_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    db = SessionLocal()
    created_alerts: List[DetectionAlert] = []
    updated_alerts = 0
    try:
        if processed_ids:
            mark_logs_analyzed(db, processed_ids)

        result = run_rule_engine(processed_ids)
        alerts = result.get("alerts", [])

        # --- PHASE B: INVARIANT CHECKS ---
        # Ensure 1 log <= 1 detection per rule
        seen_log_usage = set()
        
        for alert_payload in alerts:
            # Check invariants
            rule_name = alert_payload.get("rule_name")
            pids = (alert_payload.get("evidence") or {}).get("processed_ids") or []
            for pid in pids:
                key = (rule_name, pid)
                if key in seen_log_usage:
                    logger.error(
                        "invariant violation: log reused in multiple alerts for same rule", 
                        extra={"rule": rule_name, "processed_id": pid}
                    )
                seen_log_usage.add(key)
            # ---------------------------------

            fingerprint = alert_payload.get("fingerprint")
            if not fingerprint:
                continue
            existing = db.query(DetectionAlert).filter(DetectionAlert.fingerprint == fingerprint).first()
            record = create_or_update_alert_from_analysis(db, alert_payload)
            if not record:
                continue
            if existing:
                updated_alerts += 1
            else:
                created_alerts.append(record)
                logger.info("alert created", extra={"alert_id": record.id, "fingerprint": record.fingerprint})
                broadcast_sync({
                    "type": "NEW_DETECTION",
                    "data": {
                        "id": record.id,
                        "title": record.summary or record.rule_name,
                        "severity": record.severity,
                        "rule_id": record.rule_id
                    }
                })
            evidence = alert_payload.get("evidence") or {}
            processed_ids_from_evidence = evidence.get("processed_ids") or []
            fingerprints = evidence.get("fingerprints") or []
            if processed_ids_from_evidence or fingerprints:
                _mark_alert_on_logs(db, processed_ids_from_evidence, fingerprints, record.id)

        for alert in created_alerts:
            run_ai_investigation_and_maybe_create_incident_task(alert.id, False)

        return {
            "status": "ok",
            "processed_logs_checked": result.get("processed_logs_checked", 0),
            "correlation_findings_checked": result.get("correlation_findings_checked", 0),
            "alerts_created": len(created_alerts),
            "alerts_updated": updated_alerts
        }
    except Exception:
        logger.exception("pipeline automation failed")
        return {"status": "failed", "alerts_created": 0, "alerts_updated": 0}
    finally:
        db.close()


def _build_alert_payload(alert: DetectionAlert) -> Dict[str, Any]:
    evidence = _parse_json(alert.evidence_json, {})
    created_at = _ensure_utc(alert.created_at)
    return {
        "id": alert.id,
        "created_at": created_at.isoformat() if created_at else None,
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
        center = _ensure_utc(alert.created_at) or datetime.now(timezone.utc)
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

    def _parse_ts(value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            return _ensure_utc(value)
        if isinstance(value, str) and value.strip():
            try:
                normalized = value.replace("Z", "+00:00")
                parsed = datetime.fromisoformat(normalized)
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except Exception:
                return None
        return None

    def _normalize_confidence(value: Any) -> int:
        try:
            return int(max(0, min(100, int(value))))
        except Exception:
            return 0

    def _extract_technique_id(value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        if text.lower().startswith("mitre:"):
            text = text.split(":", 1)[-1].strip()
        match = re.search(r"(T\d{4}(?:\.\d{3})?)", text, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        token = text.split()[0].strip()
        return token.upper() if token else ""

    def _normalize_mitre(matches: Any, tags: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        candidates: List[Any] = []
        if isinstance(matches, list):
            candidates.extend(matches)
        elif matches:
            candidates.append(matches)
        if isinstance(tags, list):
            for tag in tags:
                tag_value = str(tag or "").strip()
                if tag_value.lower().startswith("mitre:"):
                    candidates.append(tag_value.split(":", 1)[-1])
        for item in candidates:
            if isinstance(item, dict):
                tid = item.get("technique_id") or item.get("id") or item.get("technique")
                name = item.get("technique_name") or item.get("name")
                tactics = item.get("tactics") or item.get("tactic") or []
                if not isinstance(tactics, list):
                    tactics = [tactics]
                tid = _extract_technique_id(tid or name)
                if not tid:
                    continue
                score = _normalize_confidence(item.get("confidence_score") or item.get("confidence") or 0)
                normalized.append(
                    {
                        "technique_id": tid,
                        "technique_name": str(name or "").strip(),
                        "tactics": [str(t).strip() for t in tactics if str(t).strip()],
                        "confidence_score": score,
                        "reasoning": item.get("reasoning") or "",
                        "matched_signals": item.get("matched_signals") or []
                    }
                )
            elif isinstance(item, str):
                tid = _extract_technique_id(item)
                if not tid:
                    continue
                normalized.append(
                    {
                        "technique_id": tid,
                        "technique_name": "",
                        "tactics": [],
                        "confidence_score": 0,
                        "reasoning": "",
                        "matched_signals": []
                    }
                )
        dedup: Dict[str, Dict[str, Any]] = {}
        for match in normalized:
            tid = match.get("technique_id")
            if tid and tid not in dedup:
                dedup[tid] = match
        return list(dedup.values())

    def _is_hash_type(ioc_type: str) -> bool:
        return ioc_type in {"sha256", "md5", "hash"}

    def _filter_iocs(ioc_intel: Dict[str, Any]) -> List[Dict[str, Any]]:
        matches = ioc_intel.get("ioc_matches") or []
        filtered: List[Dict[str, Any]] = []
        for match in matches:
            if not isinstance(match, dict):
                continue
            ioc_value = str(
                match.get("ioc")
                or match.get("value")
                or match.get("indicator")
                or match.get("match")
                or ""
            ).strip()
            if not ioc_value:
                continue
            verdict = str(match.get("verdict") or match.get("risk") or "unknown").lower().strip()
            confidence = _normalize_confidence(match.get("confidence") or match.get("confidence_score") or 0)
            ioc_type = str(match.get("type") or match.get("ioc_type") or "").lower().strip()
            if verdict == "benign":
                continue
            if verdict != "malicious" and confidence < 50:
                continue
            if _is_hash_type(ioc_type) and verdict != "malicious":
                continue
            filtered.append(
                {
                    "ioc": ioc_value,
                    "type": ioc_type or "unknown",
                    "verdict": verdict,
                    "confidence": confidence,
                    "evidence": match.get("evidence") or match.get("reason") or ""
                }
            )
        return filtered

    def _extract_remote(fields: Dict[str, Any]) -> Dict[str, Optional[str]]:
        remote_ip = fields.get("remote_ip") or fields.get("destination_ip") or fields.get("dst_ip")
        remote_domain = fields.get("domain") or fields.get("query") or fields.get("remote_domain")
        return {"remote_ip": remote_ip, "remote_domain": remote_domain}

    def _event_signature(event: Dict[str, Any]) -> Dict[str, Optional[str]]:
        return {
            "command_line": event.get("command_line"),
            "process_chain": f"{event.get('parent_process') or ''}|{event.get('process_name') or ''}".strip("|")
        }

    key_events: List[Dict[str, Any]] = []
    seen_command = set()
    seen_chain = set()
    seen_iocs = set()
    event_candidates: List[Dict[str, Any]] = []
    for log in processed_logs:
        ts = _parse_ts(log.get("timestamp"))
        if not ts or ts < start or ts > end:
            continue
        severity_score = int(log.get("severity_score") or 0)
        if severity_score < 40:
            continue
        fields = log.get("fields") or {}
        ioc_intel = fields.get("ioc_intel") or {}
        mitre_filtered = _normalize_mitre(fields.get("mitre_matches") or [], log.get("tags") or [])
        ioc_filtered = _filter_iocs(ioc_intel)
        event = {
            "process_name": fields.get("process_name"),
            "command_line": fields.get("command_line"),
            "parent_process": fields.get("parent_process") or fields.get("parent_name"),
            "username": fields.get("username") or fields.get("user"),
            "severity_score": severity_score,
            "mitre_matches": mitre_filtered,
            "ioc_matches": ioc_filtered
        }
        event.update(_extract_remote(fields))
        signature = _event_signature(event)
        command_line = signature.get("command_line") or ""
        chain = signature.get("process_chain") or ""
        ioc_values = [m.get("ioc") for m in ioc_filtered if m.get("ioc")]
        if command_line and command_line in seen_command:
            continue
        if chain and chain in seen_chain:
            continue
        if any(ioc in seen_iocs for ioc in ioc_values):
            continue
        if command_line:
            seen_command.add(command_line)
        if chain:
            seen_chain.add(chain)
        for ioc in ioc_values:
            seen_iocs.add(ioc)
        event_candidates.append(
            {
                "event": event,
                "timestamp": ts,
                "has_ioc": 1 if ioc_filtered else 0,
                "severity_score": severity_score
            }
        )

    event_candidates.sort(
        key=lambda item: (item["has_ioc"], item["severity_score"], item["timestamp"]),
        reverse=True
    )
    for item in event_candidates[:10]:
        key_events.append(item["event"])

    ioc_index: Dict[str, Dict[str, Any]] = {}
    verdict_counts: Dict[str, int] = {}
    for event in key_events:
        for match in event.get("ioc_matches") or []:
            ioc = match.get("ioc")
            if not ioc:
                continue
            ioc_index[ioc] = match
            verdict = str(match.get("verdict") or "unknown").lower()
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

    mitre_index: Dict[str, Dict[str, Any]] = {}
    for event in key_events:
        for match in event.get("mitre_matches") or []:
            tid = str(match.get("technique_id") or match.get("technique_name") or "").strip()
            if tid:
                mitre_index[tid] = match

    risk_signals: List[Dict[str, Any]] = []
    for finding in correlation_findings:
        entities = finding.get("entities") or {}
        risk_signals.append(
            {
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "confidence_score": finding.get("confidence_score"),
                "reasons": entities.get("correlation_reasons") or [],
                "correlation_score": entities.get("correlation_score") or 0
            }
        )

    return {
        "asset": {
            "agent_id": evidence.get("agent_id"),
            "hostname": evidence.get("hostname"),
            "alert_id": alert.id,
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "created_at": alert.created_at.isoformat() if alert.created_at else None
        },
        "key_events": key_events,
        "ioc_summary": {
            "total_iocs": len(ioc_index),
            "verdict_counts": verdict_counts,
            "high_confidence_iocs": list(ioc_index.values())
        },
        "mitre_summary": list(mitre_index.values()),
        "risk_signals": risk_signals
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
    created_at = _ensure_utc(alert.created_at)
    seed = f"{alert.id}|{alert.rule_id}|{created_at.isoformat() if created_at else ''}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _severity_from_confidence(score: int) -> str:
    normalized = int(max(0, min(100, score)))
    if normalized >= 90:
        return "critical"
    if normalized >= 70:
        return "high"
    if normalized >= 40:
        return "medium"
    return "low"


def _severity_rank(value: Any) -> int:
    sev = str(value or "").strip().lower()
    if sev == "critical":
        return 4
    if sev == "high":
        return 3
    if sev == "medium":
        return 2
    if sev == "low":
        return 1
    if sev == "info":
        return 0
    return 1


def _normalize_tactic(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _extract_technique_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.lower().startswith("mitre:"):
        text = text.split(":", 1)[-1].strip()
    match = re.search(r"(T\d{4}(?:\.\d{3})?)", text, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    token = text.split()[0].strip()
    return token.upper() if token else ""


def _collect_mitre_indicators(
    alert: DetectionAlert,
    context: Dict[str, Any],
    investigation: Dict[str, Any]
) -> Dict[str, List[str]]:
    techniques: List[str] = []
    tactics: List[str] = []

    def _add_items(items: Any) -> None:
        if not items:
            return
        if not isinstance(items, list):
            items = [items]
        for item in items:
            if isinstance(item, dict):
                tid = item.get("technique_id") or item.get("id") or item.get("technique")
                name = item.get("technique_name") or item.get("name")
                tid = _extract_technique_id(tid or name)
                if tid:
                    techniques.append(tid)
                tac = item.get("tactics") or item.get("tactic") or []
                if not isinstance(tac, list):
                    tac = [tac]
                for t in tac:
                    tactic_value = _normalize_tactic(t)
                    if tactic_value:
                        tactics.append(tactic_value)
            elif isinstance(item, str):
                tid = _extract_technique_id(item)
                if tid:
                    techniques.append(tid)

    alert_mitre = _parse_json(alert.mitre_json, [])
    _add_items(alert_mitre)
    _add_items(context.get("mitre_summary") or [])
    _add_items(investigation.get("mitre_mapping") or [])
    for event in context.get("key_events") or []:
        if not isinstance(event, dict):
            continue
        _add_items(event.get("mitre_matches") or [])

    return {
        "techniques": list(dict.fromkeys(techniques)),
        "tactics": list(dict.fromkeys(tactics))
    }


def _has_correlated_activity(context: Dict[str, Any]) -> bool:
    return bool(context.get("risk_signals") or [])


def compute_confidence_breakdown(
    alert: DetectionAlert,
    context: Dict[str, Any],
    investigation: Dict[str, Any]
) -> Dict[str, Any]:
    context = context or {}
    investigation = investigation or {}
    alert_sev = str(alert.severity or "").strip().lower()
    rule_confidence = {
        "critical": 30,
        "high": 25,
        "medium": 15,
        "low": 5
    }.get(alert_sev, 0)

    mitre = _collect_mitre_indicators(alert, context, investigation)
    tactics = {str(t).strip().lower().replace("-", "_").replace(" ", "_") for t in mitre.get("tactics") or []}
    high_risk_tactics = {
        "credential_access",
        "persistence",
        "lateral_movement",
        "command_and_control",
        "impact",
        "defense_evasion"
    }
    medium_risk_tactics = {
        "execution",
        "privilege_escalation",
        "discovery",
        "collection",
        "exfiltration"
    }
    mitre_confidence = 0
    mitre_reason = ""
    if tactics.intersection(high_risk_tactics):
        mitre_confidence = 25
        mitre_reason = "High-risk MITRE tactic"
    elif tactics.intersection(medium_risk_tactics):
        mitre_confidence = 15
        mitre_reason = "Medium-risk MITRE tactic"
    elif tactics:
        mitre_confidence = 5
        mitre_reason = "Low-risk MITRE tactic"

    ioc_matches = _parse_json(alert.ioc_json, [])
    if not isinstance(ioc_matches, list):
        ioc_matches = []
    ioc_summary = context.get("ioc_summary") or {}
    high_conf_iocs = ioc_summary.get("high_confidence_iocs") or []
    combined_iocs = []
    if isinstance(ioc_matches, list):
        combined_iocs.extend(ioc_matches)
    if isinstance(high_conf_iocs, list):
        combined_iocs.extend(high_conf_iocs)
    ioc_verdicts = {str(item.get("verdict") or "unknown").strip().lower() for item in combined_iocs if isinstance(item, dict)}
    ioc_confidence = 0
    ioc_reason = ""
    if "malicious" in ioc_verdicts:
        ioc_confidence = 20
        ioc_reason = "Malicious IOC"
    elif "suspicious" in ioc_verdicts:
        ioc_confidence = 10
        ioc_reason = "Suspicious IOC"

    correlation_items = context.get("risk_signals")
    if not isinstance(correlation_items, list):
        correlation_items = context.get("correlation_findings") or []
    correlation_count = len(correlation_items) if isinstance(correlation_items, list) else 0
    correlation_confidence = 0
    correlation_reason = ""
    if correlation_count >= 2:
        correlation_confidence = 15
        correlation_reason = "Correlated activity across multiple events"
    elif correlation_count == 1:
        correlation_confidence = 5
        correlation_reason = "Single related event correlation"

    status = str(investigation.get("status") or "").lower()
    ai_score = investigation.get("confidence_score")
    if ai_score is None and isinstance(investigation.get("assessment"), dict):
        ai_score = investigation.get("assessment", {}).get("confidence_score")
    try:
        if status and status != "completed":
            ai_score = 0
        ai_score = int(ai_score or 0)
    except Exception:
        ai_score = 0
    ai_score = int(max(0, min(100, ai_score)))
    ai_confidence = int(max(0, min(10, ai_score // 10)))

    breakdown = {
        "rule_confidence": int(rule_confidence),
        "mitre_confidence": int(mitre_confidence),
        "ioc_confidence": int(ioc_confidence),
        "correlation_confidence": int(correlation_confidence),
        "ai_confidence": int(ai_confidence)
    }
    total = sum(breakdown.values())
    original_breakdown = dict(breakdown)
    original_total = total
    confidence_floor_applied = False
    if alert_sev == "critical" and total < 70:
        ai_confidence_value = int(breakdown.get("ai_confidence") or 0)
        rule_confidence_value = int(breakdown.get("rule_confidence") or 0)
        mitre_options = [v for v in [0, 5, 15, 25] if v >= int(breakdown.get("mitre_confidence") or 0)]
        ioc_options = [v for v in [0, 10, 20] if v >= int(breakdown.get("ioc_confidence") or 0)]
        correlation_options = [v for v in [0, 5, 15] if v >= int(breakdown.get("correlation_confidence") or 0)]
        best_choice = None
        for mitre_value in mitre_options:
            for ioc_value in ioc_options:
                for correlation_value in correlation_options:
                    candidate_total = rule_confidence_value + ai_confidence_value + mitre_value + ioc_value + correlation_value
                    if candidate_total >= 70:
                        if best_choice is None or candidate_total < best_choice["total"]:
                            best_choice = {
                                "mitre": mitre_value,
                                "ioc": ioc_value,
                                "correlation": correlation_value,
                                "total": candidate_total
                            }
        if best_choice is None:
            best_choice = {
                "mitre": mitre_options[-1],
                "ioc": ioc_options[-1],
                "correlation": correlation_options[-1],
                "total": rule_confidence_value + ai_confidence_value + mitre_options[-1] + ioc_options[-1] + correlation_options[-1]
            }
        breakdown["mitre_confidence"] = int(best_choice["mitre"])
        breakdown["ioc_confidence"] = int(best_choice["ioc"])
        breakdown["correlation_confidence"] = int(best_choice["correlation"])
        total = int(best_choice["total"])
        confidence_floor_applied = True

    recomputed = sum(breakdown.values())
    if recomputed != total:
        logger.error(
            "confidence breakdown mismatch",
            extra={"alert_id": alert.id, "computed": total, "recomputed": recomputed}
        )
        total = recomputed

    lines = ["Confidence derived from:"]
    if breakdown["rule_confidence"]:
        rule_label = {
            "critical": "Critical detection rule",
            "high": "High severity rule",
            "medium": "Medium severity rule",
            "low": "Low severity rule"
        }.get(alert_sev, "Rule severity signal")
        lines.append(f"- {rule_label} (+{breakdown['rule_confidence']})")
    if breakdown["mitre_confidence"]:
        reason = mitre_reason or ("Critical severity floor adjustment" if confidence_floor_applied and breakdown["mitre_confidence"] != original_breakdown.get("mitre_confidence") else "")
        if reason:
            lines.append(f"- {reason} (+{breakdown['mitre_confidence']})")
    if breakdown["ioc_confidence"]:
        reason = ioc_reason or ("Critical severity floor adjustment" if confidence_floor_applied and breakdown["ioc_confidence"] != original_breakdown.get("ioc_confidence") else "")
        if reason:
            lines.append(f"- {reason} (+{breakdown['ioc_confidence']})")
    if breakdown["correlation_confidence"]:
        reason = correlation_reason or ("Critical severity floor adjustment" if confidence_floor_applied and breakdown["correlation_confidence"] != original_breakdown.get("correlation_confidence") else "")
        if reason:
            lines.append(f"- {reason} (+{breakdown['correlation_confidence']})")
    if breakdown["ai_confidence"]:
        lines.append(f"- AI assessment (+{breakdown['ai_confidence']})")
    if confidence_floor_applied and total > original_total:
        lines.append(f"- Critical severity floor applied (+{int(total - original_total)})")

    return {
        "confidence_score": int(total),
        "confidence_breakdown": breakdown,
        "confidence_explanation": "\n".join(lines),
        "confidence_floor_applied": confidence_floor_applied,
        "ai_input_score": int(ai_score)
    }


def _apply_confidence(
    db: Session,
    alert: DetectionAlert,
    context: Dict[str, Any],
    investigation: Dict[str, Any]
) -> Dict[str, Any]:
    confidence = compute_confidence_breakdown(alert, context, investigation)
    updates = {
        "confidence_breakdown": confidence.get("confidence_breakdown") or {},
        "confidence_explanation": confidence.get("confidence_explanation") or "",
        "confidence_floor_applied": bool(confidence.get("confidence_floor_applied"))
    }
    _update_evidence(alert, updates)
    alert.confidence_score = int(confidence.get("confidence_score") or 0)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return confidence


def evaluate_incident_policy(
    alert: DetectionAlert,
    context: Dict[str, Any],
    investigation: Dict[str, Any],
    record: Optional[AIInvestigation]
) -> Dict[str, Any]:
    """
    Deterministic Incident Promotion Policy (v1.0)
    
    Decides if a detection + AI investigation should become an incident.
    This policy is authoritative, explicit, and fail-closed.
    
    Inputs:
    - alert: The source detection
    - context: Enrichment context (MITRE, IOCs, etc.)
    - investigation: The AI's JSON output
    - record: The AI investigation DB record
    
    Returns:
    - decision: "allow" or "deny"
    - reason: Specific policy rule matched
    - metadata: Policy version and inputs used
    """
    policy_version = "v1.0-deterministic"
    
    # --- FAIL-CLOSED PRE-CHECKS ---
    if not record:
        return {"decision": "deny", "reason": "no_ai_record", "policy": policy_version}
    
    if record.status != "completed":
        return {"decision": "deny", "reason": "ai_investigation_incomplete", "policy": policy_version}
        
    # Gather Inputs
    alert_sev = str(alert.severity or "").strip().lower()
    mitre = _collect_mitre_indicators(alert, context, investigation)
    tactics = set(mitre.get("tactics") or [])
    techniques = set(mitre.get("techniques") or [])
    
    ai_is_incident = bool(record.is_incident)
    ai_confidence = int(record.confidence_score or 0)
    ai_threshold = int(getattr(settings, "INCIDENT_AI_MIN_CONFIDENCE", 60) or 60)
    
    # --- POLICY RULES ---
    
    # RULE 1: AI Confirmed Incident
    # If AI explicitly says "YES" and confidence is high enough -> PROMOTE
    if ai_is_incident and ai_confidence >= ai_threshold:
        return {
            "decision": "allow",
            "reason": "rule_ai_confirmed",
            "policy": policy_version,
            "source": "ai",
            "meta": {"ai_confidence": ai_confidence, "threshold": ai_threshold}
        }

    # RULE 2: Critical Severity Deterministic
    # If the alert is CRITICAL -> PROMOTE (Safety Net)
    if alert_sev == "critical":
        return {
            "decision": "allow",
            "reason": "rule_critical_severity",
            "policy": policy_version,
            "source": "deterministic",
            "meta": {"severity": "critical"}
        }
        
    # RULE 3: High-Risk MITRE Tactic
    # If HIGH severity AND High-Risk Tactic -> PROMOTE
    high_risk_tactics = {
        "credential_access",
        "persistence",
        "lateral_movement",
        "command_and_control",
        "impact",
        "defense_evasion"
    }
    if alert_sev == "high" and tactics.intersection(high_risk_tactics):
        return {
            "decision": "allow",
            "reason": "rule_high_risk_mitre_tactic",
            "policy": policy_version,
            "source": "deterministic",
            "meta": {"tactics": list(tactics.intersection(high_risk_tactics))}
        }

    # RULE 4: Specific High-Risk Techniques
    # If specific critical techniques are present -> PROMOTE
    # T1003 (OS Credential Dumping), T1059 (Command and Scripting Interpreter), etc.
    high_risk_prefixes = ("T1003", "T1059", "T1021", "T1046")
    matched_techniques = [t for t in techniques if t.startswith(high_risk_prefixes)]
    if matched_techniques:
        return {
            "decision": "allow",
            "reason": "rule_high_risk_technique",
            "policy": policy_version,
            "source": "deterministic",
            "meta": {"techniques": matched_techniques}
        }
        
    # RULE 5: Correlated Activity
    # If there are correlated findings in context -> PROMOTE
    if _has_correlated_activity(context):
        return {
            "decision": "allow",
            "reason": "rule_correlated_activity",
            "policy": policy_version,
            "source": "deterministic",
            "meta": {"correlation": "present"}
        }

    # DEFAULT: DENY
    return {
        "decision": "deny",
        "reason": "no_policy_match",
        "policy": policy_version,
        "source": "none"
    }


def should_promote_to_incident(
    alert: DetectionAlert,
    context: Dict[str, Any],
    investigation: Dict[str, Any],
    record: Optional[AIInvestigation]
) -> Dict[str, Any]:
    # Delegate to the explicit policy layer
    policy_result = evaluate_incident_policy(alert, context, investigation, record)
    
    is_allowed = policy_result["decision"] == "allow"
    reason = policy_result.get("reason") or "unknown"
    source = policy_result.get("source") or "none"
    policy_ver = policy_result.get("policy")
    
    # Structured Audit Log
    logger.info(
        "incident promotion policy evaluated",
        extra={
            "alert_id": alert.id,
            "rule_name": alert.rule_name,
            "decision": policy_result["decision"],
            "reason": reason,
            "policy_version": policy_ver,
            "meta": policy_result.get("meta")
        }
    )
    
    # Map back to expected legacy format for compatibility
    # Note: incident_blocked is true if it was CRITICAL but Denied
    alert_sev = str(alert.severity or "").strip().lower()
    incident_blocked = (alert_sev == "critical" and not is_allowed)
    
    return {
        "is_incident": is_allowed,
        "promotion_reason": reason,
        "promotion_source": source,
        "incident_blocked": incident_blocked
    }


def _ensure_ai_decision(alert: DetectionAlert, context: Dict[str, Any], investigation: AIInvestigation) -> Dict[str, Any]:
    status = str(investigation.status or "").lower()
    if status != "completed":
        return {"should_create": False, "reason": "AI investigation not completed"}
    confidence = int(investigation.confidence_score or 0)
    min_conf = int(getattr(settings, "INCIDENT_AI_MIN_CONFIDENCE", 60) or 60)
    if not investigation.is_incident:
        return {"should_create": False}
    if confidence < min_conf:
        return {"should_create": False, "reason": "AI confidence below incident threshold"}

    decision = decide_incident(alert, build_incident_context(SessionLocal(), alert))
    if decision.get("should_create") and decision.get("fingerprint"):
        decision["confidence_score"] = max(int(decision.get("confidence_score") or 0), confidence)
        decision["severity"] = investigation.incident_severity or decision.get("severity") or "medium"
        decision["reason"] = "AI investigation confirmed incident"
        decision["source"] = "ai_investigation"
        return decision
    evidence = context.get("evidence") or {}
    related_fps = []
    for log in context.get("processed_logs") or []:
        fp = log.get("fingerprint")
        if fp:
            related_fps.append(fp)
    return {
        "should_create": True,
        "severity": investigation.incident_severity or "medium",
        "confidence_score": confidence,
        "reason": "AI investigation confirmed incident",
        "source": "ai_investigation",
        "title": f"Incident: {alert.rule_name}",
        "summary": alert.summary or "AI investigation confirmed incident",
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
        logger.info("ai investigation started", extra={"alert_id": alert_id})

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
                _update_evidence(alert, {"ai_status": existing.status, "latest_investigation_id": existing.id})
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

        raw_output = ""
        try:
            reasons: List[str] = []
            score = 0
            for signal in context.get("risk_signals") or []:
                rs = signal.get("reasons") or []
                if isinstance(rs, list):
                    reasons.extend([str(r) for r in rs if str(r)])
                s = int(signal.get("correlation_score") or 0)
                score = max(score, s)
            if reasons or score:
                _update_evidence(alert, {"correlation_reasons": reasons[:6], "correlation_score": score})
                db.add(alert)
                db.commit()

            max_retries = int(getattr(settings, "AI_MAX_RETRIES", 2) or 2)
            retry_delay = int(getattr(settings, "AI_RETRY_DELAY_SECONDS", 2) or 2)
            max_retries = max(1, max_retries)
            total_timeout = (60 * max_retries) + (retry_delay * max(0, max_retries - 1)) + 5
            ai_result = await asyncio.wait_for(
                ai_service.investigate_alert(alert_payload, context),
                timeout=total_timeout
            )
            result = ai_result.get("result") or {}
            raw_output = ai_result.get("raw_output") or ""
            record.raw_response = ai_result.get("raw_response") or ""
            record.retry_count = int(ai_result.get("retry_count") or 0)
            record.last_retry_reason = ai_result.get("last_retry_reason")
            if not isinstance(result, dict) or not result:
                failure_payload = _default_investigation_payload()
                record.status = "failed"
                record.is_incident = False
                record.incident_severity = "none"
                record.confidence_score = 0
                record.error_message = "empty_llm_response"
                record.failure_reason = "empty_llm_response"
                record.investigation_json = json.dumps(failure_payload)
                record.investigation_text = raw_output
            else:
                result.setdefault("summary", "Summary unavailable.")
                result.setdefault("case_notes", "Case notes unavailable.")
                result.setdefault("confidence_score", int(result.get("confidence_score") or 0))
                result.setdefault("is_incident", bool(result.get("is_incident")))
                result.setdefault("incident_severity", str(result.get("incident_severity") or "none"))
                record.investigation_json = json.dumps(result)
                record.investigation_text = raw_output
                record.confidence_score = int(result.get("confidence_score") or 0)
                status_flag = str(result.get("status") or "").lower()
                error_message = result.get("error_message")
                if status_flag == "failed" or error_message:
                    failure_payload = _default_investigation_payload()
                    record.status = "failed"
                    record.is_incident = False
                    record.incident_severity = "none"
                    record.error_message = str(error_message) if error_message else "model_reported_failure"
                    record.failure_reason = record.error_message
                    record.investigation_json = json.dumps(failure_payload)
                else:
                    record.status = "completed"
                    record.is_incident = bool(result.get("is_incident"))
                    record.incident_severity = str(result.get("incident_severity") or "none")
                    record.error_message = None
                    record.failure_reason = None
            logger.info(
                "ai investigation completed",
                extra={
                    "alert_id": alert_id,
                    "status": record.status,
                    "confidence_score": record.confidence_score,
                    "is_incident": record.is_incident
                }
            )
        except asyncio.TimeoutError as exc:
            failure_payload = _default_investigation_payload()
            record.investigation_json = json.dumps(failure_payload)
            record.investigation_text = raw_output
            record.raw_response = raw_output
            record.confidence_score = 0
            record.is_incident = False
            record.incident_severity = "none"
            record.status = "failed"
            failure_reason = str(exc) or "ollama_timeout"
            record.error_message = failure_reason
            record.failure_reason = failure_reason
            record.retry_count = int(getattr(settings, "AI_MAX_RETRIES", 2) or 2)
            record.last_retry_reason = "timeout"
            logger.exception("ai investigation timeout", extra={"alert_id": alert_id})
        except Exception as exc:
            failure_payload = _default_investigation_payload()
            record.investigation_json = json.dumps(failure_payload)
            record.investigation_text = raw_output
            record.raw_response = raw_output
            record.confidence_score = 0
            record.is_incident = False
            record.incident_severity = "none"
            record.status = "failed"
            failure_reason = str(exc) or "automation_error"
            record.error_message = failure_reason
            record.failure_reason = failure_reason
            record.retry_count = int(getattr(settings, "AI_MAX_RETRIES", 2) or 2)
            record.last_retry_reason = "automation_error"
            logger.exception("ai investigation failed", extra={"alert_id": alert_id})

        db.add(record)
        db.commit()
        db.refresh(record)

        updates = {
            "ai_status": record.status,
            "ai_error": record.error_message,
            "latest_investigation_id": record.id
        }

        investigation = _parse_json(record.investigation_json, {})
        promotion = should_promote_to_incident(alert, context, investigation, record)
        final_is_incident = bool(promotion.get("is_incident"))
        promotion_reason = str(promotion.get("promotion_reason") or "")
        promotion_source = str(promotion.get("promotion_source") or "none")
        incident_blocked = bool(promotion.get("incident_blocked"))
        ai_is_incident = bool(record.is_incident)

        if incident_blocked:
            updates["incident_blocked"] = True
            logger.error(
                "critical incident blocked",
                extra={"alert_id": alert_id, "promotion_source": promotion_source}
            )

        if record.status == "completed":
            incident_severity = str(record.incident_severity or "").strip().lower()
            if final_is_incident and incident_severity in {"low", "medium", "high", "critical"}:
                alert.severity = incident_severity
            else:
                alert.severity = _severity_from_confidence(int(record.confidence_score or 0))

        investigation_payload = _parse_json(record.investigation_json, {})
        if not isinstance(investigation_payload, dict):
            investigation_payload = {}
        investigation_payload["status"] = record.status
        investigation_payload["confidence_score"] = int(record.confidence_score or 0)
        confidence = compute_confidence_breakdown(alert, context, investigation_payload)
        alert.confidence_score = int(confidence.get("confidence_score") or 0)
        updates.update(
            {
                "confidence_breakdown": confidence.get("confidence_breakdown") or {},
                "confidence_explanation": confidence.get("confidence_explanation") or "",
                "confidence_floor_applied": bool(confidence.get("confidence_floor_applied"))
            }
        )
        investigation_payload["confidence_breakdown"] = confidence.get("confidence_breakdown") or {}
        investigation_payload["confidence_explanation"] = confidence.get("confidence_explanation") or ""
        record.investigation_json = json.dumps(investigation_payload)
        db.add(record)
        db.commit()
        db.refresh(record)

        if final_is_incident:
            if promotion_source == "ai":
                decision = _ensure_ai_decision(alert, context, record)
            else:
                decision = decide_incident(alert, build_incident_context(db, alert))
                decision["should_create"] = True
            if promotion_reason:
                decision["reason"] = promotion_reason

            # --- PHASE B: PROMOTION SAFETY GATE ---
            gate_required = ["confidence_score", "severity", "reason"]
            gate_missing = [f for f in gate_required if not decision.get(f)]
            
            if gate_missing:
                logger.error(
                    "promotion blocked (safety gate)",
                    extra={
                        "alert_id": alert_id,
                        "missing_fields": gate_missing
                    }
                )
                final_is_incident = False
            else:
                logger.info(
                    "promotion safety gate passed",
                    extra={
                        "alert_id": alert_id,
                        "rule_name": alert.rule_name,
                        "severity": decision.get("severity"),
                        "confidence": decision.get("confidence_score"),
                        "promotion_reason": decision.get("reason")
                    }
                )
            # --------------------------------------

            if promotion_source == "deterministic":
                decision_sev = decision.get("severity") or alert.severity
                if _severity_rank(decision_sev) < _severity_rank(alert.severity):
                    decision["severity"] = alert.severity
            
            incident = None
            if final_is_incident:
                incident = create_or_link_incident(db, decision, alert)
            
            if incident:
                updates["incident_id"] = incident.id
                logger.info(
                    "incident created",
                    extra={
                        "alert_id": alert_id,
                        "incident_id": incident.id,
                        "confidence_score": record.confidence_score
                    }
                )
            else:
                logger.info("incident skipped (dedup or create failed)", extra={"alert_id": alert_id})
        else:
            threshold = int(getattr(settings, "INCIDENT_AI_MIN_CONFIDENCE", 60) or 60)
            logger.info(
                "incident skipped (gating)",
                extra={
                    "alert_id": alert_id,
                    "status": record.status,
                    "is_incident": record.is_incident,
                    "confidence_score": record.confidence_score,
                    "threshold": threshold
                }
            )

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
                AIInvestigation.status.in_(["completed", "failed", "running", "timeout", "empty"])
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
