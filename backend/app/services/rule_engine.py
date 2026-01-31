import json
import os
import hashlib
import uuid
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


def _load_processed_logs(window_seconds: int, max_logs: int) -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        # Load recent processed logs in descending time order.
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
            if ts and ts < cutoff:
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


def _has_encoded_command(event: Dict[str, Any]) -> bool:
    tags = event.get("tags") or []
    raw = str(event.get("raw") or "").lower()
    message = str(event.get("message") or "").lower()
    combined = f"{raw} {message}"
    return "encoded_command" in tags or ("powershell" in combined and ("-enc" in combined or "-encodedcommand" in combined))


def _has_mitre_matches(event: Dict[str, Any]) -> bool:
    return len(event.get("mitre_matches") or []) > 0


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


def _build_signal_alert(
    event: Dict[str, Any],
    window_seconds: int,
    reasons: List[str]
) -> Dict[str, Any]:
    alert_id = str(uuid.uuid4())
    fingerprint_key = event.get("fingerprint") or str(event.get("id") or alert_id)
    fingerprint = _signal_fingerprint(fingerprint_key, event.get("ts"), window_seconds)
    summary = "Signal detected: " + ", ".join(reasons)
    evidence = {
        "event_ids": [event.get("event_id")] if event.get("event_id") else [],
        "processed_ids": [event.get("id")] if event.get("id") is not None else [],
        "fingerprints": [event.get("fingerprint")] if event.get("fingerprint") else [],
        "summary": summary
    }
    return {
        "alert_id": alert_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rule_id": "RULE-SIGNAL",
        "rule_name": "Signal Detected",
        "severity": "low",
        "confidence_score": 25,
        "category": "signal",
        "mitre": event.get("mitre_matches") or [],
        "ioc_matches": (event.get("ioc_intel") or {}).get("ioc_matches") or [],
        "evidence": {**evidence, "alert_id": alert_id},
        "recommended_actions": [
            "Review the triggering signal in context",
            "Confirm whether the activity is expected",
            "Run AI investigation for deeper assessment"
        ],
        "status": "open",
        "fingerprint": fingerprint,
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


def run_rule_engine() -> Dict[str, Any]:
    """
    Executes all detection rules over recent processed logs and correlation findings.
    """
    window_seconds = int(os.getenv("RULE_WINDOW_SECONDS", "600"))
    max_logs = int(os.getenv("RULE_MAX_LOGS", "500"))
    max_findings = int(os.getenv("RULE_MAX_FINDINGS", "200"))
    group_by = os.getenv("RULE_GROUP_BY", "hostname")

    logs = _load_processed_logs(window_seconds, max_logs)
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
            alerts.extend(rule.evaluate(logs, findings, context))
        except Exception:
            # Prevent a single broken rule from stopping the entire engine
            continue

    coverage = _collect_alert_coverage(alerts)
    signal_alerts: List[Dict[str, Any]] = []
    for event in logs:
        event_id = event.get("event_id")
        processed_id = event.get("id")
        fingerprint = event.get("fingerprint")
        if (
            (event_id and event_id in coverage["event_ids"])
            or (processed_id is not None and processed_id in coverage["processed_ids"])
            or (fingerprint and fingerprint in coverage["fingerprints"])
        ):
            continue
        reasons: List[str] = []
        if _has_mitre_matches(event):
            reasons.append("MITRE match")
        if _has_encoded_command(event):
            reasons.append("Encoded command")
        if _has_ioc_matches(event):
            reasons.append("IOC signal")
        if _has_correlation_hit(event, findings):
            reasons.append("Correlation hit")
        if not reasons:
            continue
        signal_alerts.append(_build_signal_alert(event, window_seconds, reasons))

    alerts.extend(signal_alerts)

    return {
        "processed_logs_checked": len(logs),
        "correlation_findings_checked": len(findings),
        "alerts": alerts
    }
