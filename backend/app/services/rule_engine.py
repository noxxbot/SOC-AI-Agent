import json
import os
import hashlib
import uuid
import re
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set

from app.database.db import SessionLocal
from app.models.models import ProcessedLog
from app.models.correlation_finding import CorrelationFinding
from app.services.rules.rule_bruteforce_ssh import BruteForceSSHRule
from app.services.rules.rule_powershell_encoded import PowerShellEncodedRule
from app.services.rules.rule_suspicious_dns import SuspiciousDNSRule
from app.services.rules.rule_malicious_ioc import MaliciousIOCRule
from app.services.rules.rule_mitre_high_confidence import MitreHighConfidenceRule
from app.services.rules.rule_correlation_high import CorrelationHighSeverityRule
from app.services.rules.rule_powershell_network_sequence import PowerShellNetworkSequenceRule

logger = logging.getLogger(__name__)


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


def _normalize_mitre_matches(value: Any, tags: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    candidates: List[Any] = []
    if isinstance(value, list):
        candidates.extend(value)
    elif value:
        candidates.append(value)
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
            score = item.get("confidence_score") or item.get("confidence") or 0
            try:
                score = int(score)
            except Exception:
                score = 0
            items.append(
                {
                    "technique_id": tid,
                    "technique_name": str(name or "").strip(),
                    "tactics": [str(t).strip() for t in tactics if str(t).strip()],
                    "confidence_score": int(max(0, min(100, score))),
                    "reasoning": item.get("reasoning") or "",
                    "matched_signals": item.get("matched_signals") or []
                }
            )
        elif isinstance(item, str):
            tid = _extract_technique_id(item)
            if not tid:
                continue
            items.append(
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
    for match in items:
        tid = match.get("technique_id")
        if tid and tid not in dedup:
            dedup[tid] = match
    return list(dedup.values())


def _load_processed_logs(window_seconds: int, max_logs: int, processed_ids: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        if processed_ids:
            # ID-based mode: Load specific logs, bypassing limits
            logs = (
                db.query(ProcessedLog)
                .filter(ProcessedLog.id.in_(processed_ids))
                .order_by(ProcessedLog.timestamp.desc(), ProcessedLog.created_at.desc())
                .all()
            )
            # Log any requested IDs that were missing
            found_ids = {log.id for log in logs}
            for pid in processed_ids:
                if pid not in found_ids:
                    logger.debug("log skipped", extra={"reason": "missing_id_in_db", "processed_id": pid})
        else:
            # Time-window mode: Load recent logs with limit
            logs = (
                db.query(ProcessedLog)
                .order_by(ProcessedLog.timestamp.desc(), ProcessedLog.created_at.desc())
                .limit(max_logs)
                .all()
            )

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        results: List[Dict[str, Any]] = []
        for log in logs:
            ts = _normalize_timestamp(log.timestamp or log.created_at)
            
            # Only enforce time window if NOT in explicit ID mode
            if not processed_ids:
                if ts and ts < cutoff:
                    logger.debug("log skipped", extra={"reason": "timestamp_window", "processed_id": log.id})
                    continue

            # Decode JSON fields for rule evaluation.
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
            normalized_mitre = _normalize_mitre_matches(fields.get("mitre_matches", []), tags)
            results.append(
                {
                    "id": log.id,
                    "agent_id": log.agent_id,
                    "hostname": log.hostname,
                    "timestamp": ts.isoformat(),
                    "ts": ts,
                    "category": log.category,
                    "event_type": log.event_type,
                    "severity_score": log.severity_score,
                    "severity_raw": fields.get("severity_raw") or fields.get("raw_severity"),
                    "message": log.message,
                    "raw": log.raw,
                    "fields": fields,
                    "iocs": iocs,
                    "tags": tags,
                    "fingerprint": log.fingerprint,
                    "mitre_matches": normalized_mitre,
                    "ioc_intel": fields.get("ioc_intel", {})
                }
            )
        return results
    finally:
        db.close()


def _load_correlation_findings(window_seconds: int, max_findings: int) -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        # Load recent correlation findings for promotion rules.
        findings = (
            db.query(CorrelationFinding)
            .order_by(CorrelationFinding.created_at.desc())
            .limit(max_findings)
            .all()
        )
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        results: List[Dict[str, Any]] = []
        for f in findings:
            created = _normalize_timestamp(f.created_at)
            if created and created < cutoff:
                continue
            entities = _parse_json(f.entities_json, {})
            evidence = _parse_json(f.evidence_json, [])
            mitre = _parse_json(f.mitre_json, [])
            ioc = _parse_json(f.ioc_json, {})
            results.append(
                {
                    "id": f.id,
                    "created_at": created.isoformat() if created else None,
                    "ts": created,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence_score": f.confidence_score,
                    "entities": entities,
                    "evidence": evidence,
                    "mitre_summary": mitre,
                    "ioc_summary": ioc,
                    "fingerprint": f.fingerprint,
                    "status": f.status
                }
            )
        return results
    finally:
        db.close()


def _parse_json(value: Any, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _load_rules():
    # Explicit rule list keeps evaluation deterministic and ordered.
    return [
        BruteForceSSHRule(),
        PowerShellEncodedRule(),
        PowerShellNetworkSequenceRule(),
        SuspiciousDNSRule(),
        MaliciousIOCRule(),
        MitreHighConfidenceRule(),
        CorrelationHighSeverityRule()
    ]


def _bucket_time(ts: Optional[datetime], window_seconds: int) -> str:
    base = ts or datetime.now(timezone.utc)
    bucket_seconds = max(1, window_seconds)
    epoch = int(base.timestamp())
    bucket = epoch - (epoch % bucket_seconds)
    return datetime.fromtimestamp(bucket, tz=timezone.utc).isoformat()


def _signal_fingerprint(key: str, ts: Optional[datetime], window_seconds: int) -> str:
    bucket = _bucket_time(ts, window_seconds)
    payload = f"RULE-SIGNAL|{key}|{bucket}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _critical_fallback_fingerprint(processed_id: int) -> str:
    payload = f"{processed_id}critical_fallback"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _mitre_detection_fingerprint(processed_id: int) -> str:
    payload = f"{processed_id}mitre_high_risk"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _ioc_detection_fingerprint(processed_id: int) -> str:
    payload = f"{processed_id}ioc_hit"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _normalize_tactic(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _mitre_high_risk_matches(event: Dict[str, Any]) -> Dict[str, Any]:
    matches = event.get("mitre_matches") or []
    high_risk = {
        "execution",
        "credential_access",
        "lateral_movement",
        "persistence",
        "command_and_control",
        "defense_evasion"
    }
    tactics = set()
    for match in matches:
        for tactic in match.get("tactics") or []:
            norm = _normalize_tactic(tactic)
            if norm in high_risk:
                tactics.add(norm)
    return {"matches": matches if tactics else [], "tactics": sorted(tactics)}


def _mitre_detection_confidence(matches: List[Dict[str, Any]], severity_score: int) -> int:
    max_conf = 0
    for match in matches:
        try:
            score = int(match.get("confidence_score") or 0)
        except Exception:
            score = 0
        max_conf = max(max_conf, score)
    base = max(max_conf, severity_score)
    return int(max(70, min(100, base)))


def _ioc_detection_details(event: Dict[str, Any]) -> Dict[str, Any]:
    ioc_intel = event.get("ioc_intel") or {}
    matches = ioc_intel.get("ioc_matches") or []
    if not isinstance(matches, list):
        matches = []
    summary = ioc_intel.get("ioc_summary") or {}
    allowed_types = {"domain", "ip", "ipv4", "ipv6", "sha256", "md5", "hash", "process", "process_name"}
    filtered = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        ioc_type = str(match.get("type") or match.get("ioc_type") or "").strip().lower()
        if ioc_type in allowed_types:
            filtered.append(match)
    verdicts = {str(m.get("verdict") or "").strip().lower() for m in filtered}
    risk = ""
    if "malicious" in verdicts:
        risk = "malicious"
    elif "suspicious" in verdicts:
        risk = "suspicious"
    confidence = 0
    try:
        confidence = int(summary.get("confidence") or 0)
    except Exception:
        confidence = 0
    if risk == "malicious":
        confidence = max(80, confidence)
    elif risk == "suspicious":
        confidence = max(60, confidence)
    else:
        confidence = 0
    return {"risk": risk, "confidence": confidence, "matches": matches}


def _has_encoded_command(event: Dict[str, Any]) -> bool:
    tags = event.get("tags") or []
    raw = str(event.get("raw") or "").lower()
    message = str(event.get("message") or "").lower()
    combined = f"{raw} {message}"
    return "encoded_command" in tags or ("powershell" in combined and ("-enc" in combined or "-encodedcommand" in combined))


def _has_mitre_matches(event: Dict[str, Any]) -> bool:
    return len(event.get("mitre_matches") or []) > 0


def _mitre_confidence_contribution(matches: List[Dict[str, Any]]) -> int:
    if not matches:
        return 0
    techniques = {m.get("technique_id") for m in matches if m.get("technique_id")}
    base = len(techniques) * 5
    high = {"impact", "exfiltration", "command_and_control"}
    higher = {"execution", "persistence", "defense_evasion", "credential_access"}
    medium = {"discovery", "collection", "lateral_movement"}
    tactic_bonus = 0
    for match in matches:
        for tactic in match.get("tactics") or []:
            norm = str(tactic).strip().lower().replace("-", "_").replace(" ", "_")
            if norm in high:
                tactic_bonus = max(tactic_bonus, 10)
            elif norm in higher:
                tactic_bonus = max(tactic_bonus, 8)
            elif norm in medium:
                tactic_bonus = max(tactic_bonus, 5)
    return int(max(0, min(35, base + tactic_bonus)))


def _has_ioc_matches(event: Dict[str, Any]) -> bool:
    ioc_intel = event.get("ioc_intel") or {}
    matches = ioc_intel.get("ioc_matches") or []
    if matches:
        return True
    iocs = event.get("iocs") or {}
    return any(iocs.get(k) for k in ["ips", "domains", "sha256", "md5", "cves"])


def _has_correlation_hit(event: Dict[str, Any], findings: List[Dict[str, Any]]) -> bool:
    event_id = event.get("id")
    fingerprint = event.get("fingerprint")
    hostname = event.get("hostname")
    agent_id = event.get("agent_id")
    for finding in findings or []:
        for evidence in finding.get("evidence") or []:
            if event_id is not None and evidence.get("event_id") == event_id:
                return True
            if fingerprint and evidence.get("fingerprint") == fingerprint:
                return True
        entities = finding.get("entities") or {}
        if hostname and entities.get("hostname") == hostname:
            return True
        if agent_id and entities.get("agent_id") == agent_id:
            return True
    return False


def _normalize_severity(value: Any) -> str:
    return str(value or "").strip().lower()


def _severity_rank(value: Any) -> int:
    sev = _normalize_severity(value)
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


def _severity_from_context(raw_severity: Any, severity_score: Any, current: Any) -> Dict[str, Any]:
    raw_value = _normalize_severity(raw_severity)
    score_value = 0
    try:
        score_value = int(severity_score or 0)
    except Exception:
        score_value = 0
    current_value = _normalize_severity(current) or "low"
    target = current_value
    source = "rule"
    reason = "rule"
    if raw_value == "critical":
        target = "critical"
        source = "raw"
        reason = "critical_log"
    elif score_value >= 70:
        target = "high"
        source = "score"
        reason = "severity_score"
    if _severity_rank(target) > _severity_rank(current_value):
        return {"severity": target, "source": source, "reason": reason}
    return {"severity": current_value, "source": source, "reason": reason}


def _build_signal_alert(
    event: Dict[str, Any],
    window_seconds: int,
    reasons: List[str]
) -> Dict[str, Any]:
    alert_id = str(uuid.uuid4())
    fingerprint_key = event.get("fingerprint") or str(event.get("id") or alert_id)
    fingerprint = _signal_fingerprint(fingerprint_key, event.get("ts"), window_seconds)
    mitre_matches = event.get("mitre_matches") or []
    mitre_ids = [m.get("technique_id") for m in mitre_matches if m.get("technique_id")]
    summary = "Signal detected: " + ", ".join(reasons)
    if mitre_matches and reasons == ["MITRE match"]:
        summary = "MITRE Technique Observed: " + ", ".join(mitre_ids)
    evidence = {
        "event_ids": [event.get("event_id")] if event.get("event_id") else [],
        "processed_ids": [event.get("id")] if event.get("id") is not None else [],
        "fingerprints": [event.get("fingerprint")] if event.get("fingerprint") else [],
        "summary": summary
    }
    severity_info = _severity_from_context(
        event.get("severity_raw"),
        event.get("severity_score"),
        "low"
    )
    detection_reason = "signal: " + ", ".join(reasons) if reasons else "signal"
    if mitre_matches:
        detection_reason = "mitre_technique_observed"
    mitre_contribution = _mitre_confidence_contribution(mitre_matches)
    return {
        "alert_id": alert_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rule_id": "RULE-SIGNAL",
        "rule_name": "Signal Detected",
        "severity": severity_info["severity"],
        "confidence_score": int(max(0, min(100, 25 + mitre_contribution))),
        "category": "signal",
        "mitre": mitre_matches,
        "ioc_matches": (event.get("ioc_intel") or {}).get("ioc_matches") or [],
        "evidence": {
            **evidence,
            "alert_id": alert_id,
            "severity_raw": event.get("severity_raw"),
            "severity_score": event.get("severity_score"),
            "severity_source": severity_info["source"],
            "detection_reason": detection_reason,
            "mitre_source": "log" if mitre_matches else None,
            "mitre_confidence": mitre_contribution if mitre_matches else 0
        },
        "recommended_actions": [
            "Review the triggering signal in context",
            "Confirm whether the activity is expected",
            "Run AI investigation for deeper assessment"
        ],
        "status": "open",
        "fingerprint": fingerprint,
        "summary": summary
    }


def _build_critical_fallback_alert(
    event: Dict[str, Any],
    confidence_score: int
) -> Dict[str, Any]:
    processed_id = event.get("id")
    summary = "Critical log detected without matching rule"
    return {
        "alert_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rule_id": "RULE-CRITICAL-FALLBACK",
        "rule_name": "RULE-CRITICAL-FALLBACK",
        "severity": "critical",
        "confidence_score": int(max(0, min(100, confidence_score))),
        "category": "signal",
        "mitre": event.get("mitre_matches") or [],
        "ioc_matches": (event.get("ioc_intel") or {}).get("ioc_matches") or [],
        "evidence": {
            "event_ids": [event.get("event_id")] if event.get("event_id") else [],
            "processed_ids": [processed_id] if processed_id is not None else [],
            "fingerprints": [event.get("fingerprint")] if event.get("fingerprint") else [],
            "summary": summary,
            "severity_raw": event.get("severity_raw"),
            "severity_score": event.get("severity_score"),
            "detection_reason": "critical_fallback"
        },
        "recommended_actions": [
            "Review the critical log context for immediate risks",
            "Validate whether the activity is expected",
            "Run AI investigation for deeper assessment"
        ],
        "status": "open",
        "fingerprint": _critical_fallback_fingerprint(processed_id),
        "summary": summary
    }


def _build_mitre_high_risk_alert(
    event: Dict[str, Any],
    confidence_score: int
) -> Dict[str, Any]:
    processed_id = event.get("id")
    summary = "High-risk MITRE technique observed"
    return {
        "alert_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rule_id": "RULE-MITRE-HIGH-RISK",
        "rule_name": "RULE-MITRE-HIGH-RISK",
        "severity": "high",
        "confidence_score": int(max(0, min(100, confidence_score))),
        "category": "mitre",
        "mitre": event.get("mitre_matches") or [],
        "ioc_matches": (event.get("ioc_intel") or {}).get("ioc_matches") or [],
        "evidence": {
            "event_ids": [event.get("event_id")] if event.get("event_id") else [],
            "processed_ids": [processed_id] if processed_id is not None else [],
            "fingerprints": [event.get("fingerprint")] if event.get("fingerprint") else [],
            "summary": summary,
            "severity_raw": event.get("severity_raw"),
            "severity_score": event.get("severity_score"),
            "detection_reason": "mitre_high_risk"
        },
        "recommended_actions": [
            "Review the MITRE technique context for adversary behavior",
            "Validate process lineage and user activity",
            "Run AI investigation for deeper assessment"
        ],
        "status": "open",
        "fingerprint": _mitre_detection_fingerprint(processed_id),
        "summary": summary
    }


def _build_ioc_hit_alert(
    event: Dict[str, Any],
    confidence_score: int,
    severity: str
) -> Dict[str, Any]:
    processed_id = event.get("id")
    summary = "IOC match detected in log context"
    return {
        "alert_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rule_id": "RULE-IOC-HIT",
        "rule_name": "RULE-IOC-HIT",
        "severity": severity,
        "confidence_score": int(max(0, min(100, confidence_score))),
        "category": "threat-intel",
        "mitre": event.get("mitre_matches") or [],
        "ioc_matches": (event.get("ioc_intel") or {}).get("ioc_matches") or [],
        "evidence": {
            "event_ids": [event.get("event_id")] if event.get("event_id") else [],
            "processed_ids": [processed_id] if processed_id is not None else [],
            "fingerprints": [event.get("fingerprint")] if event.get("fingerprint") else [],
            "summary": summary,
            "severity_raw": event.get("severity_raw"),
            "severity_score": event.get("severity_score"),
            "detection_reason": "ioc_hit"
        },
        "recommended_actions": [
            "Validate the IOC source and scope of exposure",
            "Check affected assets for related activity",
            "Run AI investigation for deeper assessment"
        ],
        "status": "open",
        "fingerprint": _ioc_detection_fingerprint(processed_id),
        "summary": summary
    }


def _collect_alert_coverage(alerts: List[Dict[str, Any]]) -> Dict[str, Set[Any]]:
    coverage = {"event_ids": set(), "processed_ids": set(), "fingerprints": set()}
    for alert in alerts or []:
        evidence = alert.get("evidence") or {}
        for key in ["event_ids", "processed_ids", "fingerprints"]:
            values = evidence.get(key) or []
            if isinstance(values, list):
                coverage[key].update(values)
    return coverage


def _validate_and_clamp_alert(alert: Dict[str, Any]) -> None:
    # --- PHASE B: CONFIDENCE & SEVERITY GUARDRAILS ---
    # 1. Clamp Confidence 0-100
    try:
        raw_conf = int(alert.get("confidence_score") or 0)
    except (ValueError, TypeError):
        raw_conf = 0
    
    clamped_conf = max(0, min(100, raw_conf))
    
    if clamped_conf != raw_conf:
        logger.warning(
            "confidence clamped",
            extra={
                "rule": alert.get("rule_name"),
                "original": raw_conf,
                "clamped": clamped_conf
            }
        )
    
    # 2. Severity <-> Confidence Consistency
    severity = str(alert.get("severity") or "medium").lower()
    
    # CRITICAL must be >= 50
    if severity == "critical" and clamped_conf < 50:
        logger.warning(
            "safety rail violation: critical severity with low confidence",
            extra={"rule": alert.get("rule_name"), "confidence": clamped_conf}
        )
        clamped_conf = 50 # Fail-safe adjustment
        
    # LOW must be <= 70
    if severity == "low" and clamped_conf > 70:
         logger.warning(
            "safety rail violation: low severity with high confidence",
            extra={"rule": alert.get("rule_name"), "confidence": clamped_conf}
        )
         clamped_conf = 70 # Fail-safe adjustment

    alert["confidence_score"] = clamped_conf


def run_rule_engine(processed_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Executes all detection rules over recent processed logs and correlation findings.
    """
    window_seconds = int(os.getenv("RULE_WINDOW_SECONDS", "600"))
    max_logs = int(os.getenv("RULE_MAX_LOGS", "500"))
    max_findings = int(os.getenv("RULE_MAX_FINDINGS", "200"))
    group_by = os.getenv("RULE_GROUP_BY", "hostname")

    if processed_ids:
        logger.info(f"Starting rule engine in ID-based mode for {len(processed_ids)} logs")
    else:
        logger.info("Starting rule engine in Time-Window mode")

    logs = _load_processed_logs(window_seconds, max_logs, processed_ids)
    
    for log in logs:
        if log.get("id"):
            logger.debug("log evaluated", extra={"processed_id": log.get("id")})

    findings = _load_correlation_findings(window_seconds, max_findings)
    rules = _load_rules()

    context = {
        "window_seconds": window_seconds,
        "group_by": group_by,
        "now": datetime.now(timezone.utc)
    }

    alerts: List[Dict[str, Any]] = []
    for rule in rules:
        try:
            new_alerts = rule.evaluate(logs, findings, context)
            for alert in new_alerts:
                # --- PHASE B: CONFIDENCE & SEVERITY GUARDRAILS ---
                _validate_and_clamp_alert(alert)
                # -------------------------------------------------

                evidence = alert.get("evidence") or {}
                pids = evidence.get("processed_ids") or []
                logger.info(
                    "detection created", 
                    extra={
                        "rule_name": alert.get("rule_name"),
                        "fingerprint": alert.get("fingerprint"),
                        "processed_id": pids[0] if pids else None
                    }
                )
            alerts.extend(new_alerts)
        except Exception:
            # Prevent a single broken rule from stopping the entire engine
            continue
    
    # --- PHASE B: OBSERVABILITY ---
    logger.info(
        "rule engine finished", 
        extra={
            "logs_count": len(logs), 
            "findings_count": len(findings),
            "alerts_created": len(alerts),
            "mode": "ID-based" if processed_ids else "Time-Window"
        }
    )
    # -------------------------------

    coverage = _collect_alert_coverage(alerts)
    signal_alerts: List[Dict[str, Any]] = []
    fallback_alerts: List[Dict[str, Any]] = []
    mitre_alerts: List[Dict[str, Any]] = []
    ioc_alerts: List[Dict[str, Any]] = []
    critical_score_threshold = 90
    for event in logs:
        event_id = event.get("event_id")
        processed_id = event.get("id")
        fingerprint = event.get("fingerprint")
        try:
            severity_score = int(event.get("severity_score") or 0)
        except Exception:
            severity_score = 0
        mitre_details = _mitre_high_risk_matches(event)
        mitre_matches = mitre_details.get("matches") or []
        mitre_tactics = mitre_details.get("tactics") or []
        ioc_details = _ioc_detection_details(event)
        ioc_risk = str(ioc_details.get("risk") or "").strip().lower()
        ioc_confidence = int(ioc_details.get("confidence") or 0)
        if (
            (event_id and event_id in coverage["event_ids"])
            or (processed_id is not None and processed_id in coverage["processed_ids"])
            or (fingerprint and fingerprint in coverage["fingerprints"])
        ):
            if mitre_matches:
                logger.debug(
                    "mitre detection skipped",
                    extra={
                        "processed_id": processed_id,
                        "fingerprint": fingerprint,
                        "reason": "covered_by_rule"
                    }
                )
            if ioc_risk:
                logger.debug(
                    "ioc detection skipped",
                    extra={
                        "processed_id": processed_id,
                        "fingerprint": fingerprint,
                        "reason": "covered_by_rule"
                    }
                )
            if severity_score >= critical_score_threshold:
                logger.debug(
                    "critical fallback skipped",
                    extra={
                        "processed_id": processed_id,
                        "fingerprint": fingerprint,
                        "severity_score": severity_score,
                        "reason": "covered_by_rule"
                    }
                )
            continue
        reasons: List[str] = []
        emitted = False
        if _has_mitre_matches(event):
            reasons.append("MITRE match")
        if _has_encoded_command(event):
            reasons.append("Encoded command")
        if _has_ioc_matches(event):
            reasons.append("IOC signal")
        if _has_correlation_hit(event, findings):
            reasons.append("Correlation hit")
        if _normalize_severity(event.get("severity_raw")) == "critical":
            reasons.append("Critical log")
        has_signal = False
        if reasons:
            signal_alerts.append(_build_signal_alert(event, window_seconds, reasons))
            has_signal = True
            emitted = True
            if severity_score >= critical_score_threshold:
                logger.debug(
                    "critical fallback skipped",
                    extra={
                        "processed_id": processed_id,
                        "fingerprint": fingerprint,
                        "severity_score": severity_score,
                        "reason": "signal_reasons_present"
                    }
                )
        if mitre_matches:
            if processed_id is not None:
                mitre_confidence = _mitre_detection_confidence(mitre_matches, severity_score)
                mitre_alerts.append(_build_mitre_high_risk_alert(event, mitre_confidence))
                emitted = True
                technique_ids = [m.get("technique_id") for m in mitre_matches if m.get("technique_id")]
                logger.info(
                    "mitre high risk alert created",
                    extra={
                        "processed_id": processed_id,
                        "fingerprint": fingerprint,
                        "tactics": mitre_tactics,
                        "techniques": technique_ids
                    }
                )
        if ioc_risk:
            if processed_id is not None:
                ioc_severity = "critical" if ioc_risk == "malicious" else "high"
                ioc_alerts.append(_build_ioc_hit_alert(event, ioc_confidence, ioc_severity))
                emitted = True
                logger.info(
                    "ioc hit alert created",
                    extra={
                        "processed_id": processed_id,
                        "fingerprint": fingerprint,
                        "risk": ioc_risk
                    }
                )
        if not has_signal and severity_score >= critical_score_threshold:
            if processed_id is None:
                logger.debug(
                    "critical fallback skipped",
                    extra={
                        "processed_id": processed_id,
                        "fingerprint": fingerprint,
                        "severity_score": severity_score,
                        "reason": "missing_processed_id"
                    }
                )
                continue
            fallback_alerts.append(_build_critical_fallback_alert(event, severity_score))
            emitted = True
            logger.info(
                "critical fallback alert created",
                extra={
                    "processed_id": processed_id,
                    "fingerprint": fingerprint,
                    "severity_score": severity_score
                }
            )

        if not emitted and not has_signal and not mitre_matches and not ioc_risk and severity_score < critical_score_threshold:
            logger.debug(
                "log skipped",
                extra={
                    "reason": "no_detection_conditions",
                    "processed_id": processed_id,
                    "fingerprint": fingerprint
                }
            )

    alerts.extend(signal_alerts)
    alerts.extend(fallback_alerts)
    alerts.extend(mitre_alerts)
    alerts.extend(ioc_alerts)

    logs_by_id = {event.get("id"): event for event in logs if event.get("id") is not None}
    logs_by_fingerprint = {event.get("fingerprint"): event for event in logs if event.get("fingerprint")}

    for alert in alerts:
        evidence = alert.get("evidence") or {}
        processed_ids = evidence.get("processed_ids") or []
        fingerprints = evidence.get("fingerprints") or []
        candidates: List[Dict[str, Any]] = []
        for pid in processed_ids:
            if pid in logs_by_id:
                candidates.append(logs_by_id[pid])
        for fp in fingerprints:
            if fp in logs_by_fingerprint:
                candidates.append(logs_by_fingerprint[fp])
        if candidates:
            max_score = max(int(c.get("severity_score") or 0) for c in candidates)
            raw_values = [c.get("severity_raw") for c in candidates if c.get("severity_raw")]
            raw_value = None
            for value in raw_values:
                if raw_value is None or _severity_rank(value) > _severity_rank(raw_value):
                    raw_value = value
            if evidence.get("severity_raw") is None:
                evidence["severity_raw"] = raw_value
            if evidence.get("severity_score") is None:
                evidence["severity_score"] = max_score
            if evidence.get("detection_reason") is None:
                evidence["detection_reason"] = "rule"
            severity_info = _severity_from_context(raw_value, max_score, alert.get("severity"))
            alert["severity"] = severity_info["severity"]
            if evidence.get("severity_source") is None:
                evidence["severity_source"] = severity_info["source"]
            if evidence.get("mitre_confidence") is None:
                mitre_matches = alert.get("mitre") or []
                mitre_contribution = _mitre_confidence_contribution(mitre_matches)
                if mitre_matches:
                    alert["confidence_score"] = int(
                        max(0, min(100, int(alert.get("confidence_score") or 0) + mitre_contribution))
                    )
                    evidence["mitre_confidence"] = mitre_contribution
            if (alert.get("mitre") or []) and not evidence.get("mitre_source"):
                if alert.get("category") == "correlation":
                    evidence["mitre_source"] = "correlation"
                elif alert.get("rule_id") == "RULE-SIGNAL":
                    evidence["mitre_source"] = "log"
                else:
                    evidence["mitre_source"] = "rule"
            if (alert.get("mitre") or []) and evidence.get("detection_reason") in {None, "rule", "signal"}:
                evidence["detection_reason"] = "mitre_technique_observed"
            if alert.get("mitre"):
                technique_ids = [m.get("technique_id") for m in alert.get("mitre") or [] if m.get("technique_id")]
                if technique_ids:
                    summary = str(alert.get("summary") or "")
                    if not any(tid in summary for tid in technique_ids):
                        alert["summary"] = (summary + " Techniques: " + ", ".join(technique_ids)).strip()
            alert["evidence"] = evidence

    return {
        "processed_logs_checked": len(logs),
        "correlation_findings_checked": len(findings),
        "alerts": alerts
    }
