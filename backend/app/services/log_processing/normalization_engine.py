import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _parse_timestamp(value: Any, fallback: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    if isinstance(value, str) and value.strip():
        try:
            normalized = value.replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).astimezone(timezone.utc).isoformat()
        except Exception:
            pass
    if isinstance(fallback, datetime):
        return fallback.astimezone(timezone.utc).isoformat()
    if isinstance(fallback, str) and fallback.strip():
        try:
            normalized = fallback.replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).astimezone(timezone.utc).isoformat()
        except Exception:
            pass
    return datetime.now(timezone.utc).isoformat()


def _ensure_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _normalize_log_source(log_source: str, event_type: str, fields: Dict[str, Any]) -> str:
    source = (log_source or "").strip().lower()
    if source in {"sysmon", "windows_security", "app", "audit", "network", "endpoint"}:
        return source
    if source in {"process", "performance", "system"}:
        return "endpoint"
    if source in {"auth", "security"}:
        return "audit"
    if "sysmon" in source:
        return "sysmon"
    if "security" in source:
        return "windows_security"
    if "network" in source:
        return "network"
    if "process" in (event_type or "").lower():
        return "endpoint"
    if "network" in (event_type or "").lower():
        return "network"
    if fields.get("source") == "sysmon":
        return "sysmon"
    return "other"


def _normalize_event_type(event_type: str, log_source: str, fields: Dict[str, Any]) -> str:
    et = (event_type or "").strip().lower()
    mapping = {
        "net_conn": "network_connection",
        "dns_query": "dns_query",
        "process_start": "process_start",
        "cpu_high": "cpu_high",
        "ram_high": "ram_high",
        "login_failed": "failed_login",
        "login_success": "login_success"
    }
    if et in mapping:
        return mapping[et]
    if et:
        return et
    if log_source == "network":
        return "network_connection"
    if log_source == "endpoint":
        return "process_start"
    return "other"


def _detect_category(event_type: str, log_source: str, fields: Dict[str, Any]) -> str:
    et = (event_type or "").lower()
    if "login" in et or "auth" in et:
        return "auth"
    if "process" in et:
        return "process"
    if "dns" in et:
        return "dns"
    if "network" in et:
        return "network"
    if "file" in et:
        return "file"
    if et in {"cpu_high", "ram_high"}:
        return "system"
    if log_source in {"windows_security", "audit"}:
        return "audit"
    if log_source == "app":
        return "application"
    return "other"


def _severity_score(severity_raw: str, event_type: str, fields: Dict[str, Any]) -> int:
    sr = (severity_raw or "low").lower()
    base = {
        "info": 10,
        "low": 20,
        "medium": 50,
        "warn": 40,
        "high": 80,
        "critical": 95
    }.get(sr, 20)
    if event_type in {"failed_login", "cpu_high", "ram_high"}:
        base = min(100, base + 10)
    return int(max(0, min(100, base)))


def _build_message(event_type: str, fields: Dict[str, Any]) -> str:
    et = (event_type or "event").replace("_", " ")
    if fields.get("process_name"):
        return f"{et}: {fields.get('process_name')}"
    if fields.get("remote_ip") and fields.get("remote_port"):
        return f"{et}: {fields.get('remote_ip')}:{fields.get('remote_port')}"
    return et


def normalize_log(log: Dict[str, Any], agent_id: str, hostname: str, default_ts: Any) -> Dict[str, Any]:
    event_id = str(log.get("event_id") or uuid.uuid4())
    resolved_agent_id = str(log.get("agent_id") or agent_id or "unknown")
    resolved_hostname = str(log.get("hostname") or hostname or "unknown")
    timestamp = _parse_timestamp(log.get("timestamp"), default_ts)
    log_source_raw = str(log.get("log_source") or "")
    event_type_raw = str(log.get("event_type") or "")
    severity_raw = str(log.get("severity_raw") or log.get("severity") or "low").lower()
    fields = _ensure_dict(log.get("fields") or log.get("fields_json") or {})
    raw = log.get("raw")
    message = log.get("message") or raw

    log_source = _normalize_log_source(log_source_raw, event_type_raw, fields)
    event_type = _normalize_event_type(event_type_raw, log_source, fields)
    category = _detect_category(event_type, log_source, fields)
    severity_score = _severity_score(severity_raw, event_type, fields)

    if not message:
        message = _build_message(event_type, fields)
    if not raw:
        raw = message

    return {
        "event_id": event_id,
        "agent_id": resolved_agent_id,
        "hostname": resolved_hostname,
        "timestamp": timestamp,
        "log_source": log_source,
        "event_type": event_type,
        "category": category,
        "severity_raw": severity_raw,
        "severity_score": severity_score,
        "message": message,
        "raw": raw,
        "fields": fields
    }
