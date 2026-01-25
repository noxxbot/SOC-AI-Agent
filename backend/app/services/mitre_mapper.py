import asyncio
import os
import re
from typing import Any, Dict, List, Optional

from app.services.mitre_offline import MitreOfflineService


"""
Offline-first MITRE mapping for processed logs.
Returns deterministic technique matches with minimal rule signals.
"""

_mitre_service = MitreOfflineService()


def _safe_technique_details(technique_id: str) -> Optional[Dict[str, Any]]:
    try:
        return _mitre_service.get_technique_details(technique_id)
    except Exception:
        return None


def _build_match(
    technique_id: str,
    reasoning: str,
    matched_signals: List[str],
    confidence_score: int
) -> Dict[str, Any]:
    details = _safe_technique_details(technique_id) or {}
    technique_name = details.get("name") or "Unknown Technique"
    tactics = details.get("tactics") or []
    return {
        "technique_id": technique_id,
        "technique_name": technique_name,
        "tactics": tactics,
        "confidence_score": int(max(0, min(100, confidence_score))),
        "reasoning": reasoning,
        "matched_signals": matched_signals
    }


def _text_blob(log: Dict[str, Any]) -> str:
    raw = str(log.get("raw") or "")
    message = str(log.get("message") or "")
    fields = log.get("fields") or {}
    parts = [raw, message]
    if fields:
        parts.append(str(fields))
    return " ".join(parts).lower()


def _rule_matches(log: Dict[str, Any]) -> List[Dict[str, Any]]:
    text = _text_blob(log)
    matches: List[Dict[str, Any]] = []

    if "powershell" in text:
        matches.append(_build_match("T1059.001", "PowerShell execution observed", ["powershell"], 80))

    if re.search(r"\brundll32\b", text):
        matches.append(_build_match("T1218.011", "rundll32 execution observed", ["rundll32"], 80))

    if re.search(r"\breg\s+(add|query)\b", text) or re.search(r"\breg\.exe\b", text):
        matches.append(_build_match("T1112", "Registry modification/query behavior detected", ["reg add/query"], 70))

    if re.search(r"\bdnscat2?\b|\biodine\b|\bdns\s*tunnel\b|\bdns_tunnel\b", text):
        matches.append(_build_match("T1071.004", "DNS tunneling indicators detected", ["dns tunneling"], 75))

    if re.search(r"\b-enc\b|\b-encodedcommand\b", text):
        matches.append(_build_match("T1027", "Encoded/obfuscated command observed", ["encoded command"], 65))

    return matches


def _llm_assist_enabled() -> bool:
    value = os.getenv("MITRE_LLM_ASSIST", "")
    return value.lower() in {"1", "true", "yes"}


async def _ask_llm(prompt: str) -> str:
    from app.services.ai_service import AIService
    ai_service = AIService()
    return await ai_service._ask_ollama(prompt)


def _llm_refine_matches(log: Dict[str, Any], matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not matches or not _llm_assist_enabled():
        return matches

    try:
        asyncio.get_running_loop()
        return matches
    except RuntimeError:
        pass

    shortlist = [f"{m['technique_id']} {m['technique_name']}" for m in matches]
    prompt = (
        "You are a SOC MITRE classifier. Choose the most relevant technique IDs "
        "from the shortlist only. Return ONLY JSON like: {\"keep\": [\"T1059.001\"]}.\n\n"
        f"Shortlist: {shortlist}\n"
        f"Log: {log}\n"
    )
    try:
        raw = asyncio.run(_ask_llm(prompt))
        keep = re.findall(r"T\\d{4}(?:\\.\\d{3})?", raw.upper())
        if not keep:
            return matches
        keep_set = set(keep)
        return [m for m in matches if m.get("technique_id") in keep_set]
    except Exception:
        return matches


def map_mitre_matches(log: Dict[str, Any]) -> List[Dict[str, Any]]:
    try:
        matches = _rule_matches(log)
        refined = _llm_refine_matches(log, matches)
        unique = {}
        for m in refined:
            tid = m.get("technique_id")
            if tid and tid not in unique:
                unique[tid] = m
        return list(unique.values())
    except Exception:
        return []
