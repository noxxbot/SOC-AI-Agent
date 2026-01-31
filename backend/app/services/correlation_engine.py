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


def _normalize_tactic(value: str) -> str:
    return str(value or "").strip().lower().replace("_", "-").replace(" ", "-")


def _event_tactics(event: Dict[str, Any]) -> List[str]:
    tactics: List[str] = []
    for match in event.get("mitre_matches") or []:
        for tactic in match.get("tactics") or []:
            norm = _normalize_tactic(tactic)
            if norm:
                tactics.append(norm)
    return list(dict.fromkeys(tactics))


def _is_execution_event(event: Dict[str, Any]) -> bool:
    tactics = set(_event_tactics(event))
    if "execution" in tactics:
        return True
    if _has_mitre(event, "T1059") or _has_mitre(event, "T1059.001"):
        return True
    category = str(event.get("category") or "").lower()
    event_type = str(event.get("event_type") or "").lower()
    message = str(event.get("message") or "").lower()
    raw = str(event.get("raw") or "").lower()
    if category in {"process", "execution"}:
        return True
    if "process" in event_type or "command" in event_type:
        return True
    if "powershell" in message or "powershell" in raw:
        return True
    return False


def _is_network_event(event: Dict[str, Any]) -> bool:
    return event.get("category") == "network" or str(event.get("event_type", "")).lower() in {
        "network_connection",
        "net_conn",
        "dns_query",
        "http_request"
    }


def _is_encoded_powershell(event: Dict[str, Any]) -> bool:
    message = str(event.get("message") or "").lower()
    raw = str(event.get("raw") or "").lower()
    fields = event.get("fields") or {}
    command_line = str(fields.get("command_line") or "").lower()
    combined = " ".join([message, raw, command_line])
    if "powershell" not in combined:
        return False
    return "-enc " in combined or "encodedcommand" in combined or "-encodedcommand" in combined


def _extract_ioc_values(event: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    ioc_intel = event.get("ioc_intel") or {}
    for match in ioc_intel.get("ioc_matches") or []:
        if isinstance(match, dict):
            for key in ["ioc", "value", "indicator", "match", "observable"]:
                val = match.get(key)
                if val:
                    values.append(str(val))
                    break
        elif match:
            values.append(str(match))
    iocs = event.get("iocs") or {}
    for key in ["ips", "domains", "sha256", "md5", "cves"]:
        for val in iocs.get(key) or []:
            if val:
                values.append(str(val))
    return list(dict.fromkeys(values))


def _correlation_score(
    multi_stage: bool = False,
    repeated_ioc: bool = False,
    tactic_progression: bool = False,
    rapid_sequence: bool = False
) -> int:
    score = 0
    if multi_stage:
        score += 30
    if repeated_ioc:
        score += 25
    if tactic_progression:
        score += 20
    if rapid_sequence:
        score += 15
    return int(min(100, score))


def _merge_correlation_metadata(
    entities: Dict[str, Any],
    reasons: List[str],
    score: int
) -> Dict[str, Any]:
    merged = dict(entities)
    if reasons:
        merged["correlation_reasons"] = reasons
    if score:
        merged["correlation_score"] = int(score)
    return merged


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
        reasons = ["Brute force followed by successful login"]
        score = _correlation_score(multi_stage=True)
        findings.append(
            _make_finding(
                rule_name="brute_force_success",
                title="Brute force followed by successful login",
                severity="high",
                confidence_score=85,
                events=evidence,
                entities=_merge_correlation_metadata(
                    {"src_ip": src_ip, "user": user, "hostname": hostname},
                    reasons,
                    score
                ),
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
    network_events = [e for e in filtered if _is_network_event(e)]

    ps_by_host: Dict[str, List[Dict[str, Any]]] = {}
    for e in powershell_events:
        ps_by_host.setdefault(str(e.get("hostname") or "unknown"), []).append(e)

    for hostname, ps_events in ps_by_host.items():
        related_net = [e for e in network_events if str(e.get("hostname") or "unknown") == hostname]
        if not related_net:
            continue
        evidence = ps_events[:5] + related_net[:5]
        reasons = ["PowerShell followed by outbound connection"]
        score = _correlation_score(multi_stage=True)
        findings.append(
            _make_finding(
                rule_name="powershell_network_chain",
                title="PowerShell followed by outbound connection",
                severity="high",
                confidence_score=80,
                events=evidence,
                entities=_merge_correlation_metadata({"hostname": hostname}, reasons, score),
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

    execution_events = [e for e in filtered if _is_execution_event(e)]
    exec_by_host: Dict[str, List[Dict[str, Any]]] = {}
    for e in execution_events:
        exec_by_host.setdefault(str(e.get("hostname") or "unknown"), []).append(e)
    net_by_host: Dict[str, List[Dict[str, Any]]] = {}
    for e in network_events:
        net_by_host.setdefault(str(e.get("hostname") or "unknown"), []).append(e)
    threshold_seconds = min(300, window_minutes * 60)
    for hostname, exec_events in exec_by_host.items():
        related_net = net_by_host.get(hostname) or []
        if not related_net:
            continue
        matched_events = []
        for exec_event in exec_events:
            exec_ts = _parse_ts(exec_event.get("timestamp"))
            if not exec_ts:
                continue
            net_candidates = []
            for net_event in related_net:
                net_ts = _parse_ts(net_event.get("timestamp"))
                if not net_ts:
                    continue
                if net_ts >= exec_ts and net_ts <= exec_ts + timedelta(seconds=threshold_seconds):
                    net_candidates.append(net_event)
            if net_candidates:
                matched_events = [exec_event] + net_candidates[:4]
                break
        if not matched_events:
            continue
        reasons = ["Execution followed by network activity"]
        if _is_encoded_powershell(matched_events[0]):
            reasons.append("PowerShell encoded followed by outbound connection")
        score = _correlation_score(multi_stage=True, rapid_sequence=True)
        findings.append(
            _make_finding(
                rule_name="execution_network_chain",
                title="Execution followed by network within five minutes",
                severity="high",
                confidence_score=82,
                events=matched_events,
                entities=_merge_correlation_metadata({"hostname": hostname}, reasons, score),
                mitre_summary=[{"technique_id": "T1059", "name": "Command Execution"}],
                ioc_summary={"risk": "unknown", "confidence": 25},
                recommended_actions=[
                    "Review process execution details and parent chain",
                    "Inspect outbound traffic destinations and volume",
                    "Isolate host if suspicious activity persists"
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
                    entities=_merge_correlation_metadata(
                        {"hostname": e.get("hostname"), "ioc_risk": "malicious"},
                        [],
                        0
                    ),
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
        reasons = ["Potential lateral movement across hosts"]
        score = _correlation_score(multi_stage=True)
        findings.append(
            _make_finding(
                rule_name="lateral_movement",
                title="Potential lateral movement across hosts",
                severity="medium",
                confidence_score=70,
                events=group[:12],
                entities=_merge_correlation_metadata(
                    {"src_ip": src_ip, "hosts": sorted(hosts)},
                    reasons,
                    score
                ),
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
                entities=_merge_correlation_metadata({"technique_id": tid}, [], 0),
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

    ioc_hosts: Dict[str, List[str]] = {}
    ioc_events: Dict[str, List[Dict[str, Any]]] = {}
    for e in filtered:
        hostname = str(e.get("hostname") or "unknown")
        for val in _extract_ioc_values(e):
            ioc_hosts.setdefault(val, [])
            if hostname not in ioc_hosts[val]:
                ioc_hosts[val].append(hostname)
            ioc_events.setdefault(val, []).append(e)

    for ioc_value, hosts in ioc_hosts.items():
        if len(hosts) < 2:
            continue
        reasons = ["Same IOC observed across multiple hosts"]
        score = _correlation_score(repeated_ioc=True)
        events = (ioc_events.get(ioc_value) or [])[:10]
        findings.append(
            _make_finding(
                rule_name="ioc_reuse",
                title="IOC reuse across hosts",
                severity="high",
                confidence_score=80,
                events=events,
                entities=_merge_correlation_metadata(
                    {"ioc": ioc_value, "hosts": sorted(hosts)},
                    reasons,
                    score
                ),
                mitre_summary=[],
                ioc_summary={"risk": "unknown", "confidence": 30},
                recommended_actions=[
                    "Hunt for the IOC across endpoints and network logs",
                    "Contain affected hosts to prevent lateral spread",
                    "Review related alerts for coordinated activity"
                ],
                window_minutes=window_minutes
            )
        )

    tactic_hosts: Dict[str, List[Dict[str, Any]]] = {}
    for e in filtered:
        hostname = str(e.get("hostname") or "unknown")
        if _event_tactics(e):
            tactic_hosts.setdefault(hostname, []).append(e)

    for hostname, host_events in tactic_hosts.items():
        events_with_ts = []
        for e in host_events:
            ts = _parse_ts(e.get("timestamp"))
            if ts:
                events_with_ts.append((ts, e))
        if len(events_with_ts) < 3:
            continue
        events_with_ts.sort(key=lambda x: x[0])
        initial_event = None
        execution_event = None
        c2_event = None
        for ts, event in events_with_ts:
            tactics = set(_event_tactics(event))
            if not initial_event and "initial-access" in tactics:
                initial_event = (ts, event)
                continue
            if initial_event and not execution_event and "execution" in tactics and ts >= initial_event[0]:
                execution_event = (ts, event)
                continue
            if execution_event and "command-and-control" in tactics and ts >= execution_event[0]:
                c2_event = (ts, event)
                break
        if not (initial_event and execution_event and c2_event):
            continue
        duration_seconds = (c2_event[0] - initial_event[0]).total_seconds()
        rapid = duration_seconds <= threshold_seconds
        reasons = ["MITRE tactic progression Initial Access → Execution → C2"]
        score = _correlation_score(multi_stage=True, tactic_progression=True, rapid_sequence=rapid)
        findings.append(
            _make_finding(
                rule_name="mitre_tactic_chain",
                title="MITRE tactic progression across stages",
                severity="high",
                confidence_score=88,
                events=[initial_event[1], execution_event[1], c2_event[1]],
                entities=_merge_correlation_metadata({"hostname": hostname}, reasons, score),
                mitre_summary=[
                    {"tactic": "Initial Access"},
                    {"tactic": "Execution"},
                    {"tactic": "Command and Control"}
                ],
                ioc_summary={"risk": "unknown", "confidence": 30},
                recommended_actions=[
                    "Validate initial access vector and entry point",
                    "Investigate execution artifacts and persistence",
                    "Review outbound connections for C2 indicators"
                ],
                window_minutes=window_minutes
            )
        )

    return {
        "window_minutes": window_minutes,
        "total_events_seen": len(filtered),
        "correlation_findings": findings
    }
