import json
import re
from typing import Any, Dict, List


def _unique(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        value = int(part)
        if value < 0 or value > 255:
            return False
    return True


def _collect_text(raw: str, message: str, fields: Dict[str, Any]) -> str:
    pieces = [str(raw or ""), str(message or "")]
    if fields:
        try:
            pieces.append(json.dumps(fields, sort_keys=True))
        except Exception:
            pieces.append(str(fields))
    return " ".join(pieces)


def extract_iocs(raw: str, message: str, fields: Dict[str, Any]) -> Dict[str, List[str]]:
    text = _collect_text(raw, message, fields)
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    ips = [ip for ip in ips if _is_valid_ipv4(ip)]
    domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
    domains = [d for d in domains if not re.fullmatch(r"\d+(?:\.\d+){3}", d)]
    sha256 = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
    md5 = re.findall(r"\b[a-fA-F0-9]{32}\b", text)
    cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE)
    cves = [c.upper() for c in cves]

    return {
        "ips": _unique(ips),
        "domains": _unique(domains),
        "sha256": _unique(sha256),
        "md5": _unique(md5),
        "cves": _unique(cves)
    }
