import hashlib
import json
import re
from typing import Any, Dict, List

from app.services.log_processing.ioc_extractor import extract_iocs
from app.services.ioc_mapper import map_ioc_intel
from app.services.mitre_mapper import map_mitre_matches


def _unique(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _fingerprint(payload: Dict[str, Any]) -> str:
    packed = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(packed.encode("utf-8")).hexdigest()


def _match_patterns(text: str) -> Dict[str, bool]:
    lower = text.lower()
    return {
        "powershell": bool(re.search(r"\bpowershell\b", lower)),
        "encoded_command": bool(re.search(r"(-enc|-encodedcommand)\b", lower)),
        "rundll32": bool(re.search(r"\brundll32\b", lower)),
        "regsvr32": bool(re.search(r"\bregsvr32\b", lower)),
        "certutil": bool(re.search(r"\bcertutil\b", lower)),
        "wmic": bool(re.search(r"\bwmic\b", lower)),
        "schtasks": bool(re.search(r"\bschtasks\b", lower))
    }


def _mitre_hints(matches: Dict[str, bool]) -> List[Dict[str, Any]]:
    hints = []
    if matches.get("powershell"):
        hints.append({"technique_id": "T1059", "name": "Command and Scripting Interpreter", "confidence": 0.6})
    if matches.get("encoded_command"):
        hints.append({"technique_id": "T1027", "name": "Obfuscated/Compressed Files and Information", "confidence": 0.6})
    if matches.get("rundll32") or matches.get("regsvr32"):
        hints.append({"technique_id": "T1218", "name": "System Binary Proxy Execution", "confidence": 0.6})
    if matches.get("wmic"):
        hints.append({"technique_id": "T1047", "name": "Windows Management Instrumentation", "confidence": 0.6})
    if matches.get("schtasks"):
        hints.append({"technique_id": "T1053", "name": "Scheduled Task/Job", "confidence": 0.6})
    return hints


def enrich_log(normalized_log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enriches normalized logs with IOC intel, MITRE mappings, tags, and fingerprint.
    """
    raw = str(normalized_log.get("raw") or "")
    message = str(normalized_log.get("message") or "")
    fields = normalized_log.get("fields") or {}
    iocs = extract_iocs(raw, message, fields)
    ioc_intel = map_ioc_intel(iocs)

    combined_text = " ".join([raw, message, json.dumps(fields, default=str)])
    matches = _match_patterns(combined_text)

    tags = []
    if matches.get("powershell"):
        tags.append("powershell")
    if matches.get("encoded_command"):
        tags.append("encoded_command")
    if matches.get("rundll32"):
        tags.append("rundll32")
    if matches.get("regsvr32"):
        tags.append("regsvr32")
    if matches.get("certutil"):
        tags.append("certutil")
    if matches.get("wmic"):
        tags.append("wmic")
    if matches.get("schtasks"):
        tags.append("schtasks")

    mitre_hints = _mitre_hints(matches)
    mitre_matches = map_mitre_matches(
        {
            **normalized_log,
            "fields": fields,
            "raw": raw,
            "message": message
        }
    )

    for match in mitre_matches:
        tid = match.get("technique_id")
        if tid:
            tags.append(f"mitre:{tid}")

    if iocs.get("ips"):
        tags.append("ioc:ip")
    if iocs.get("domains"):
        tags.append("ioc:domain")
    if iocs.get("sha256"):
        tags.append("ioc:sha256")
    if iocs.get("md5"):
        tags.append("ioc:md5")
    for cve in iocs.get("cves", []) or []:
        tags.append(f"cve:{cve}")

    fingerprint_payload = {
        "agent_id": normalized_log.get("agent_id"),
        "hostname": normalized_log.get("hostname"),
        "timestamp": normalized_log.get("timestamp"),
        "event_type": normalized_log.get("event_type"),
        "category": normalized_log.get("category"),
        "message": normalized_log.get("message"),
        "raw": normalized_log.get("raw"),
        "fields": normalized_log.get("fields"),
        "iocs": iocs,
        "tags": tags,
        "mitre_hints": mitre_hints,
        "mitre_matches": mitre_matches,
        "ioc_intel": ioc_intel
    }

    return {
        "iocs": iocs,
        "mitre_hints": mitre_hints,
        "mitre_matches": mitre_matches,
        "ioc_intel": ioc_intel,
        "tags": _unique(tags),
        "fingerprint": _fingerprint(fingerprint_payload)
    }
