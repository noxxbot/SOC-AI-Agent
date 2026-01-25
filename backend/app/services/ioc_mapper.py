import json
import os
from typing import Any, Dict, List


"""
Offline IOC intelligence mapper using local allow/block lists.
Defaults to unknown when no evidence exists.
"""

_ALLOWLIST = None
_BLOCKLIST = None


def _load_list(path: str, default: Dict[str, List[str]]) -> Dict[str, List[str]]:
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {k: list(data.get(k, [])) for k in default.keys()}
    except Exception:
        return default


def _load_lists() -> None:
    global _ALLOWLIST, _BLOCKLIST
    if _ALLOWLIST is not None and _BLOCKLIST is not None:
        return
    base = os.path.join("app", "data", "ioc")
    allow_path = os.path.join(base, "allowlist.json")
    block_path = os.path.join(base, "blocklist.json")
    default = {"ips": [], "domains": [], "sha256": [], "md5": []}
    _ALLOWLIST = _load_list(allow_path, default)
    _BLOCKLIST = _load_list(block_path, default)


def _summary_from_verdict(verdict: str, confidence: int, notes: str) -> Dict[str, Any]:
    return {"risk": verdict, "confidence": confidence, "notes": notes}


def map_ioc_intel(iocs: Dict[str, List[str]]) -> Dict[str, Any]:
    _load_lists()
    allowlist = _ALLOWLIST or {"ips": [], "domains": [], "sha256": [], "md5": []}
    blocklist = _BLOCKLIST or {"ips": [], "domains": [], "sha256": [], "md5": []}

    ioc_matches: List[Dict[str, Any]] = []
    verdicts: List[str] = []

    for ip in iocs.get("ips", []) or []:
        if ip in blocklist.get("ips", []):
            ioc_matches.append({"ioc": ip, "type": "ip", "verdict": "malicious", "source": "offline_blocklist", "details": "Matched local blocklist"})
            verdicts.append("malicious")
        elif ip in allowlist.get("ips", []):
            ioc_matches.append({"ioc": ip, "type": "ip", "verdict": "benign", "source": "offline_allowlist", "details": "Matched local allowlist"})
            verdicts.append("benign")
        else:
            ioc_matches.append({"ioc": ip, "type": "ip", "verdict": "unknown", "source": "offline_allowlist", "details": "No local intel match"})
            verdicts.append("unknown")

    for domain in iocs.get("domains", []) or []:
        if domain in blocklist.get("domains", []):
            ioc_matches.append({"ioc": domain, "type": "domain", "verdict": "malicious", "source": "offline_blocklist", "details": "Matched local blocklist"})
            verdicts.append("malicious")
        elif domain in allowlist.get("domains", []):
            ioc_matches.append({"ioc": domain, "type": "domain", "verdict": "benign", "source": "offline_allowlist", "details": "Matched local allowlist"})
            verdicts.append("benign")
        else:
            ioc_matches.append({"ioc": domain, "type": "domain", "verdict": "unknown", "source": "offline_allowlist", "details": "No local intel match"})
            verdicts.append("unknown")

    for sha256 in iocs.get("sha256", []) or []:
        if sha256 in blocklist.get("sha256", []):
            ioc_matches.append({"ioc": sha256, "type": "sha256", "verdict": "malicious", "source": "offline_blocklist", "details": "Matched local blocklist"})
            verdicts.append("malicious")
        elif sha256 in allowlist.get("sha256", []):
            ioc_matches.append({"ioc": sha256, "type": "sha256", "verdict": "benign", "source": "offline_allowlist", "details": "Matched local allowlist"})
            verdicts.append("benign")
        else:
            ioc_matches.append({"ioc": sha256, "type": "sha256", "verdict": "unknown", "source": "offline_allowlist", "details": "No local intel match"})
            verdicts.append("unknown")

    for md5 in iocs.get("md5", []) or []:
        if md5 in blocklist.get("md5", []):
            ioc_matches.append({"ioc": md5, "type": "md5", "verdict": "malicious", "source": "offline_blocklist", "details": "Matched local blocklist"})
            verdicts.append("malicious")
        elif md5 in allowlist.get("md5", []):
            ioc_matches.append({"ioc": md5, "type": "md5", "verdict": "benign", "source": "offline_allowlist", "details": "Matched local allowlist"})
            verdicts.append("benign")
        else:
            ioc_matches.append({"ioc": md5, "type": "md5", "verdict": "unknown", "source": "offline_allowlist", "details": "No local intel match"})
            verdicts.append("unknown")

    for cve in iocs.get("cves", []) or []:
        ioc_matches.append({"ioc": cve, "type": "cve", "verdict": "suspicious", "source": "cve_detected", "details": "CVE indicator detected"})
        verdicts.append("suspicious")

    if "malicious" in verdicts:
        summary = _summary_from_verdict("malicious", 90, "At least one IOC matched local blocklist")
    elif "suspicious" in verdicts:
        summary = _summary_from_verdict("suspicious", 60, "CVE or suspicious indicators detected without confirmation")
    elif "benign" in verdicts:
        summary = _summary_from_verdict("benign", 80, "IOCs matched local allowlist")
    elif verdicts:
        summary = _summary_from_verdict("unknown", 30, "IOCs found but no local intel matches")
    else:
        summary = _summary_from_verdict("unknown", 20, "No IOCs detected")

    return {"ioc_summary": summary, "ioc_matches": ioc_matches}
