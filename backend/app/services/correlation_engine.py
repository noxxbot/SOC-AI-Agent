import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


"""
Rule-based correlation engine for processed logs.
"""


def _parse_ts(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            normalized = value.replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).astimezone(timezone.utc)
        except Exception:
            return None
    return None


def _bucket_time(ts: datetime, window_minutes: int) -> str:
    bucket_seconds = max(1, window_minutes * 60)
    epoch = int(ts.timestamp())
    bucket = epoch - (epoch % bucket_seconds)
    return datetime.fromtimestamp(bucket, tz=timezone.utc).isoformat()


def _fingerprint(rule_name: str, entity_key: str, bucket_start: str) -> str:
    payload = f"{rule_name}|{entity_key}|{bucket_start}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _event_time_range(events: List[Dict[str, Any]]) -> Tuple[str, str]:
    times = [e["timestamp"] for e in events if e.get("timestamp")]
    if not times:
        now = datetime.now(timezone.utc).isoformat()
        return now, now
    return min(times), max(times)


def _make_finding(
    rule_name: str,
    title: str,
    severity: str,
    confidence_score: int,
    events: List[Dict[str, Any]],
    entities: Dict[str, Any],
    mitre_summary: List[Dict[str, Any]],
    ioc_summary: Dict[str, Any],
    recommended_actions: List[str],
    window_minutes: int
) -> Dict[str, Any]:
    start, end = _event_time_range(events)
    bucket_start = _bucket_time(_parse_ts(start) or datetime.now(timezone.utc), window_minutes)
    entity_key = "|".join([str(entities.get(k, "")) for k in sorted(entities.keys())]) or "none"
    fingerprint = _fingerprint(rule_name, entity_key, bucket_start)
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_name": rule_name,
        "title": title,
        "severity": severity,
        "confidence_score": int(confidence_score),
        "time_range": {"start": start, "end": end},
        "entities": entities,
        "evidence": [
            {
                "event_id": e.get("id"),
                "fingerprint": e.get("fingerprint"),
                "timestamp": e.get("timestamp")
            }
            for e in events
        ],
        "mitre_summary": mitre_summary,
        "ioc_summary": ioc_summary,
        "recommended_actions": recommended_actions,
        "fingerprint": fingerprint
    }


def _extract_src_ip(event: Dict[str, Any]) -> Optional[str]:
    fields = event.get("fields") or {}
    return fields.get("source_ip") or fields.get("src_ip") or fields.get("remote_ip")


def _extract_user(event: Dict[str, Any]) -> Optional[str]:
    fields = event.get("fields") or {}
    return fields.get("user") or fields.get("username")


def _has_mitre(event: Dict[str, Any], technique_id: str) -> bool:
    matches = event.get("mitre_matches") or []
    for m in matches:
        if str(m.get("technique_id", "")).upper() == technique_id.upper():
            return True
    return False


def correlate_events(events: List[Dict[str, Any]], window_minutes: int) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=window_minutes)
    filtered = []
    for event in events:
        ts = _parse_ts(event.get("timestamp"))
        if not ts:
            continue
        if ts >= window_start:
            filtered.append(event)

    findings: List[Dict[str, Any]] = []

    failed_logins = [
        e for e in filtered
        if str(e.get("event_type", "")).lower() in {"failed_login", "login_failed"}
        or (e.get("category") == "auth" and "failed" in str(e.get("event_type", "")).lower())
    ]
    success_logins = [
        e for e in filtered
        if str(e.get("event_type", "")).lower() in {"login_success", "success_login"}
        or (e.get("category") == "auth" and "success" in str(e.get("event_type", "")).lower())
    ]

    brute_groups: Dict[str, List[Dict[str, Any]]] = {}
    for e in failed_logins:
        key = f"{_extract_src_ip(e)}|{_extract_user(e)}|{e.get('hostname')}"
        brute_groups.setdefault(key, []).append(e)

    for key, group in brute_groups.items():
        if len(group) < 5:
            continue
        src_ip, user, hostname = key.split("|")
        success = [
            s for s in success_logins
            if _extract_src_ip(s) == src_ip and _extract_user(s) == user and s.get("hostname") == hostname
        ]
        if not success:
            continue
        evidence = group[:10] + success[:3]
        findings.append(
            _make_finding(
                rule_name="brute_force_success",
                title="Brute force followed by successful login",
                severity="high",
                confidence_score=85,
                events=evidence,
                entities={"src_ip": src_ip, "user": user, "hostname": hostname},
                mitre_summary=[{"technique_id": "T1110", "name": "Brute Force"}],
                ioc_summary={"risk": "unknown", "confidence": 20},
                recommended_actions=[
                    "Block source IP temporarily",
                    "Force password reset for affected user",
                    "Review authentication logs for other targets"
                ],
                window_minutes=window_minutes
            )
        )

    powershell_events = [
        e for e in filtered
        if _has_mitre(e, "T1059.001")
        or "mitre:T1059.001" in (e.get("tags") or [])
        or "powershell" in str(e.get("message", "")).lower()
        or "powershell" in str(e.get("raw", "")).lower()
    ]
    network_events = [
        e for e in filtered
        if e.get("category") == "network"
        or str(e.get("event_type", "")).lower() in {"network_connection", "net_conn", "dns_query", "http_request"}
    ]

    ps_by_host: Dict[str, List[Dict[str, Any]]] = {}
    for e in powershell_events:
        ps_by_host.setdefault(str(e.get("hostname") or "unknown"), []).append(e)

    for hostname, ps_events in ps_by_host.items():
        related_net = [e for e in network_events if str(e.get("hostname") or "unknown") == hostname]
        if not related_net:
            continue
        evidence = ps_events[:5] + related_net[:5]
        findings.append(
            _make_finding(
                rule_name="powershell_network_chain",
                title="PowerShell followed by outbound connection",
                severity="high",
                confidence_score=80,
                events=evidence,
                entities={"hostname": hostname},
                mitre_summary=[{"technique_id": "T1059.001", "name": "PowerShell"}],
                ioc_summary={"risk": "unknown", "confidence": 20},
                recommended_actions=[
                    "Inspect PowerShell script content and command line",
                    "Review outbound connections for C2 patterns",
                    "Isolate host if suspicious behavior persists"
                ],
                window_minutes=window_minutes
            )
        )

    for e in filtered:
        ioc_intel = e.get("ioc_intel") or {}
        summary = ioc_intel.get("ioc_summary") or {}
        if summary.get("risk") == "malicious":
            findings.append(
                _make_finding(
                    rule_name="malicious_ioc",
                    title="Malicious IOC observed",
                    severity="high",
                    confidence_score=int(summary.get("confidence") or 85),
                    events=[e],
                    entities={"hostname": e.get("hostname"), "ioc_risk": "malicious"},
                    mitre_summary=[],
                    ioc_summary={"risk": "malicious", "confidence": int(summary.get("confidence") or 85)},
                    recommended_actions=[
                        "Block the malicious IOC in perimeter controls",
                        "Hunt for related activity across endpoints",
                        "Review asset for signs of compromise"
                    ],
                    window_minutes=window_minutes
                )
            )

    lateral_groups: Dict[str, List[Dict[str, Any]]] = {}
    for e in failed_logins + success_logins:
        src_ip = _extract_src_ip(e)
        if not src_ip:
            continue
        lateral_groups.setdefault(src_ip, []).append(e)

    for src_ip, group in lateral_groups.items():
        hosts = {g.get("hostname") for g in group if g.get("hostname")}
        if len(hosts) < 3:
            continue
        findings.append(
            _make_finding(
                rule_name="lateral_movement",
                title="Potential lateral movement across hosts",
                severity="medium",
                confidence_score=70,
                events=group[:12],
                entities={"src_ip": src_ip, "hosts": sorted(hosts)},
                mitre_summary=[{"technique_id": "T1021", "name": "Remote Services"}],
                ioc_summary={"risk": "unknown", "confidence": 20},
                recommended_actions=[
                    "Review authentication activity across affected hosts",
                    "Check for credential reuse or password spraying",
                    "Add temporary blocks or MFA for targeted accounts"
                ],
                window_minutes=window_minutes
            )
        )

    mitre_groups: Dict[str, List[Dict[str, Any]]] = {}
    for e in filtered:
        for m in e.get("mitre_matches", []) or []:
            tid = m.get("technique_id")
            if tid:
                mitre_groups.setdefault(tid, []).append(e)

    for tid, group in mitre_groups.items():
        if len(group) < 3:
            continue
        tname = ""
        for m in group[0].get("mitre_matches", []) or []:
            if m.get("technique_id") == tid:
                tname = m.get("technique_name") or ""
                break
        findings.append(
            _make_finding(
                rule_name="mitre_cluster",
                title="Repeated MITRE technique activity",
                severity="medium",
                confidence_score=65,
                events=group[:12],
                entities={"technique_id": tid},
                mitre_summary=[{"technique_id": tid, "name": tname or "Technique"}],
                ioc_summary={"risk": "unknown", "confidence": 20},
                recommended_actions=[
                    "Review clustered events for common root cause",
                    "Hunt for associated tactics in the same window",
                    "Verify alert coverage for the technique"
                ],
                window_minutes=window_minutes
            )
        )

    return {
        "window_minutes": window_minutes,
        "total_events_seen": len(filtered),
        "correlation_findings": findings
    }
