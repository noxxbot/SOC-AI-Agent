import json
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

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
        alerts.extend(rule.evaluate(logs, findings, context))

    return {
        "processed_logs_checked": len(logs),
        "correlation_findings_checked": len(findings),
        "alerts": alerts
    }
