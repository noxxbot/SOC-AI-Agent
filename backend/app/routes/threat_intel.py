from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import List, Dict, Any
import json
import re

from sqlalchemy.orm import Session
from app.database.db import get_db
from app.models.models import Alert
from app.services.ai_service import AIService
from app.services.threat_intel_sources import ThreatIntelSources

# ✅ Offline MITRE loader
from app.services.mitre_offline import MitreOfflineService

router = APIRouter()

ai_service = AIService()
intel_sources = ThreatIntelSources()
mitre_service = MitreOfflineService()

# Test cases:
# - T1071
# - What is T1071 in MITRE ATT&CK?
# - Explain T1055 Process Injection
# - 8.8.8.8
# - 1.1.1.1
# - What is MFA?
# - Explain OSI model and each layer
# - How to investigate brute force login attempts?

# -------------------------
# Models
# -------------------------
class ThreatIntelRequest(BaseModel):
    query: str


class ThreatIntelResponse(BaseModel):
    summary: str
    iocs: List[str]
    mitre_mapping: List[str]
    recommended_actions: List[str]


class CorrelateThreatIntelResponse(BaseModel):
    query: str
    extracted_iocs: Dict[str, Any]
    correlated_alerts: List[Dict[str, Any]]
    external_intel: Dict[str, Any]
    ai_summary: str
    mitre_mapping: List[str] = []
    recommended_actions: List[str] = []


# -------------------------
# Keyword → CVE Mapping (Phase 2 Fix)
# -------------------------
KEYWORD_TO_CVES = {
    "log4shell": ["CVE-2021-44228"],
    "log4j": ["CVE-2021-44228"],
    "log4j2": ["CVE-2021-44228"],
    "log4shell vulnerability": ["CVE-2021-44228"],

    "printnightmare": ["CVE-2021-34527"],
    "zerologon": ["CVE-2020-1472"],
    "eternalblue": ["CVE-2017-0144"],

    "lockbit": [],
    "lockbit 3.0": [],
    "lazarus group": [],
    "apt38": [],
    "apt34": [],
    "olirig": [],
}


# -------------------------
# IOC Extraction
# -------------------------
def extract_iocs(text: str) -> Dict[str, Any]:
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text.upper())
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text)
    sha256 = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
    md5 = re.findall(r"\b[a-fA-F0-9]{32}\b", text)

    return {
        "cves": list(set(cves)),
        "ips": list(set(ips)),
        "domains": list(set(domains)),
        "sha256": list(set(sha256)),
        "md5": list(set(md5)),
    }


def is_probably_fake_cve(cve_id: str) -> bool:
    try:
        parts = cve_id.upper().split("-")
        year = int(parts[1])
        num = int(parts[2])

        if year < 1999:
            return True
        if year > 2100:
            return True
        if year == 0 or num == 0:
            return True
        if year == 9999:
            return True

        return False
    except Exception:
        return True


def has_any_external_intel(external_intel: Dict[str, Any]) -> bool:
    if not external_intel:
        return False
    if external_intel.get("nvd") and len(external_intel["nvd"]) > 0:
        return True
    if external_intel.get("cisa_kev") and len(external_intel["cisa_kev"]) > 0:
        return True
    return False


def normalize_query(q: str) -> str:
    return re.sub(r"\s+", " ", q.strip().lower())


def enrich_query_with_keywords(query: str, extracted: Dict[str, Any]) -> Dict[str, Any]:
    nq = normalize_query(query)

    for keyword, cves in KEYWORD_TO_CVES.items():
        if keyword in nq and cves:
            extracted["cves"] = list(set(extracted["cves"] + cves))

    return extracted


def build_report(
    section_label: str,
    summary: str,
    internal_evidence: str,
    external_intel: str,
    mitre_mapping: str,
    next_steps: str
) -> str:
    parts = [
        "Sentinel Intelligence Report",
        section_label,
        "",
        "Summary:",
        summary.strip() if summary else "No summary available.",
        "",
        "Internal Evidence:",
        internal_evidence.strip() if internal_evidence else "None",
        "",
        "External Intel:",
        external_intel.strip() if external_intel else "None",
        "",
        "MITRE Mapping:",
        mitre_mapping.strip() if mitre_mapping else "None",
        "",
        "Next Steps:",
        next_steps.strip() if next_steps else "No recommended actions."
    ]
    return "\n".join(parts).strip()


def summarize_mitre_match(mitre_match: Dict[str, Any]) -> str:
    if not mitre_match or not mitre_match.get("matched"):
        return "No offline MITRE match found for this query."

    match_type = mitre_match.get("match_type")
    if match_type == "technique":
        t = mitre_match.get("technique") or {}
        tid = t.get("technique_id") or "Unknown Technique ID"
        name = t.get("name") or "Unknown Technique"
        tactics = t.get("tactics", [])
        description = (t.get("description") or "")[:500]
        mitigations = t.get("mitigations", []) or []
        mitigation_names = [m.get("name") for m in mitigations if m.get("name")]
        lines = [
            f"Technique: {tid} {name}",
            f"Tactics: {', '.join(tactics)}" if tactics else "Tactics: None listed",
            f"Description: {description}" if description else "Description: Not available",
            f"Mitigations: {', '.join(mitigation_names[:5])}" if mitigation_names else "Mitigations: None listed",
            "Detection Ideas: Monitor process behavior, parent-child relationships, and suspicious command execution",
            "Response/Mitigation: Contain affected endpoints, validate least privilege, and apply relevant mitigations"
        ]
        return "\n".join(lines)

    if match_type == "tactic":
        tac = mitre_match.get("tactic") or {}
        name = tac.get("name") or "Unknown Tactic"
        shortname = tac.get("shortname")
        description = (tac.get("description") or "")[:500]
        lines = [
            f"Tactic: {name}" + (f" ({shortname})" if shortname else ""),
            f"Description: {description}" if description else "Description: Not available",
            "Detection Ideas: Align SIEM rules to this tactic and monitor related telemetry",
            "Response/Mitigation: Harden controls that reduce exposure to this tactic"
        ]
        return "\n".join(lines)

    if match_type == "group":
        g = mitre_match.get("group") or {}
        name = g.get("name") or "Unknown Group"
        aliases = g.get("aliases", []) or []
        top_techs = g.get("top_techniques", []) or []
        tech_list = []
        for t in top_techs[:8]:
            tid = t.get("technique_id")
            tname = t.get("name")
            if tid and tname:
                tech_list.append(f"{tid} {tname}")
            elif tname:
                tech_list.append(tname)
        lines = [
            f"Group: {name}",
            f"Aliases: {', '.join(aliases[:5])}" if aliases else "Aliases: None listed",
            f"Top Techniques: {', '.join(tech_list)}" if tech_list else "Top Techniques: None listed",
            "Detection Ideas: Hunt for the group’s top techniques across endpoint and network telemetry",
            "Response/Mitigation: Prioritize patching, access controls, and logging for mapped techniques"
        ]
        return "\n".join(lines)

    return "Offline MITRE match found, but details are unavailable."


# -------------------------
# Endpoint (LLM-only) - KEEP WORKING
# -------------------------
@router.post("/threat-intel", response_model=ThreatIntelResponse)
async def threat_intel_search(payload: ThreatIntelRequest):
    query = payload.query.strip()

    prompt = f"""
You are a SOC Threat Intelligence Analyst.

User Query:
{query}

Return ONLY valid JSON in this schema:
{{
  "summary": "string",
  "iocs": ["string"],
  "mitre_mapping": ["string"],
  "recommended_actions": ["string"]
}}

Rules:
- summary should be short but useful
- iocs must be list of indicators like IP/domain/hash/CVE
- mitre_mapping should contain technique IDs if possible (ex: "T1566 Phishing")
- recommended_actions must be actionable steps
"""

    raw = await ai_service._ask_ollama(prompt)

    cleaned = raw.strip().replace("```json", "").replace("```", "").strip()

    try:
        data = json.loads(cleaned)
    except Exception:
        data = {
            "summary": raw,
            "iocs": [],
            "mitre_mapping": [],
            "recommended_actions": []
        }

    return {
        "summary": str(data.get("summary", "")),
        "iocs": data.get("iocs", []) if isinstance(data.get("iocs", []), list) else [],
        "mitre_mapping": data.get("mitre_mapping", []) if isinstance(data.get("mitre_mapping", []), list) else [],
        "recommended_actions": data.get("recommended_actions", []) if isinstance(data.get("recommended_actions", []), list) else []
    }


# -------------------------
# NEW Endpoint (Phase 5 Step 2)
# Uses AI classification and routes query
# -------------------------
@router.post("/threat-intel/correlate", response_model=CorrelateThreatIntelResponse)
async def threat_intel_correlate(payload: ThreatIntelRequest, db: Session = Depends(get_db)):
    query = payload.query.strip()

    # ✅ Phase 5 Step 2: AI Query Classification
    classification = await ai_service.classify_query_type(query)
    qtype = classification.get("type", "analyst_question")
    mitre_id_match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", query, re.IGNORECASE)
    if qtype not in ["unsafe_request", "out_of_scope"] and mitre_id_match:
        qtype = "mitre_query"

    # ======================================================
    # (A) Unsafe Request -> Guardrail Block
    # ======================================================
    if qtype == "unsafe_request":
        ai_summary = ai_service.cyber_guardrail_response(query)
        return {
            "query": query,
            "extracted_iocs": {"cves": [], "ips": [], "domains": [], "sha256": [], "md5": []},
            "correlated_alerts": [],
            "external_intel": {"nvd": [], "cisa_kev": [], "otx": []},
            "ai_summary": ai_summary,
            "mitre_mapping": [],
            "recommended_actions": []
        }

    # ======================================================
    # (B) Out of scope -> Refuse & redirect
    # ======================================================
    if qtype == "out_of_scope":
        ai_summary = ai_service.out_of_scope_response(query)
        return {
            "query": query,
            "extracted_iocs": {"cves": [], "ips": [], "domains": [], "sha256": [], "md5": []},
            "correlated_alerts": [],
            "external_intel": {"nvd": [], "cisa_kev": [], "otx": []},
            "ai_summary": ai_summary,
            "mitre_mapping": [],
            "recommended_actions": []
        }

    # ======================================================
    # (C) MITRE Query -> Offline MITRE Search
    # ======================================================
    if qtype == "mitre_query":
        mitre_match: Dict[str, Any] = {"matched": False}
        mitre_mapping: List[str] = []

        mitre_id = mitre_id_match.group(0).upper() if mitre_id_match else None

        if mitre_id:
            try:
                mitre_match = mitre_service.search_any(mitre_id)
            except Exception:
                mitre_match = {"matched": False}
            if not mitre_match.get("matched"):
                try:
                    mitre_match = mitre_service.search_any(query)
                except Exception:
                    mitre_match = {"matched": False}
        else:
            try:
                mitre_match = mitre_service.search_any(query)
            except Exception:
                mitre_match = {"matched": False}

        if mitre_match.get("matched") is True:
            if mitre_match.get("match_type") == "technique":
                t = mitre_match.get("technique") or {}
                tid = t.get("technique_id")
                tname = t.get("name")
                tactics = t.get("tactics", [])

                if tid and tname:
                    mitre_mapping = [f"{tid} {tname}"]
                elif tname:
                    mitre_mapping = [str(tname)]

                if tactics:
                    mitre_mapping.append("Tactics: " + ", ".join(tactics))

            elif mitre_match.get("match_type") == "tactic":
                tac = mitre_match.get("tactic") or {}
                name = tac.get("name")
                shortname = tac.get("shortname")
                if name:
                    mitre_mapping = [f"Tactic: {name} ({shortname})" if shortname else f"Tactic: {name}"]

            elif mitre_match.get("match_type") == "group":
                g = mitre_match.get("group") or {}
                gname = g.get("name")
                if gname:
                    mitre_mapping = [gname]

        mitre_summary = summarize_mitre_match(mitre_match)
        mitre_prompt = f"""
You are a SOC Threat Intel Analyst.

User Question:
{query}

Offline MITRE Result:
{json.dumps(mitre_match, indent=2)}

STRICT RULES:
- Use ONLY the offline MITRE data above.
- Do NOT include UI titles like "Sentinel Intelligence Report" or query labels.
- Output must be clean markdown text only (no code fences, no JSON).
- Do NOT invent threat actor claims, CVEs, or techniques.
- If no offline match, say: "Offline dataset didn’t return a match" and ask for an exact technique ID.
- Prefer medium-to-detailed answers by default unless the user asks for a short answer.

Response format:
Short Answer:
(2–5 lines)

Then include only relevant sections:
MITRE Summary:
Tactics:
Technique Details:
Detection Ideas (SOC):
Mitigation / Response:
Example (realistic):
Next Steps:
"""

        try:
            mitre_out = await ai_service._ask_ollama(mitre_prompt)
            mitre_out = ai_service._clean_llm_output(mitre_out).strip()
            ai_summary = mitre_out if mitre_out else mitre_summary
        except Exception:
            ai_summary = mitre_summary

        return {
            "query": query,
            "extracted_iocs": {"cves": [], "ips": [], "domains": [], "sha256": [], "md5": []},
            "correlated_alerts": [],
            "external_intel": {"nvd": [], "cisa_kev": [], "otx": []},
            "ai_summary": ai_summary.strip(),
            "mitre_mapping": mitre_mapping,
            "recommended_actions": []
        }

    # ======================================================
    # (D) Analyst Question -> Cybersecurity Assistant Answer
    # ======================================================
    if qtype == "analyst_question":
        mitre_match: Dict[str, Any] = {"matched": False}
        try:
            mitre_match = mitre_service.search_any(query)
        except Exception:
            mitre_match = {"matched": False}

        context = {
            "mitre_match": mitre_match
        }

        try:
            analyst_answer = await ai_service.answer_cybersecurity_question(query, context=context)
        except Exception:
            analyst_answer = "Not enough data to generate an AI answer right now."

        ai_summary = analyst_answer

        return {
            "query": query,
            "extracted_iocs": {"cves": [], "ips": [], "domains": [], "sha256": [], "md5": []},
            "correlated_alerts": [],
            "external_intel": {"nvd": [], "cisa_kev": [], "otx": []},
            "ai_summary": ai_summary.strip(),
            "mitre_mapping": [],
            "recommended_actions": []
        }

    # ======================================================
    # (E) IOC Query -> Full Correlation Pipeline (your old logic)
    # ======================================================
    extracted = extract_iocs(query)
    extracted = enrich_query_with_keywords(query, extracted)

    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(50).all()

    correlated = []
    query_lower = query.lower()

    for a in alerts:
        combined_text = f"{a.title} {a.description}".lower()
        match = False

        for cve in extracted["cves"]:
            if cve.lower() in combined_text:
                match = True

        for ip in extracted["ips"]:
            if ip in combined_text:
                match = True

        for d in extracted["domains"]:
            if d.lower() in combined_text:
                match = True

        if query_lower in combined_text:
            match = True

        if match:
            correlated.append({
                "id": a.id,
                "agent_id": a.agent_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "timestamp": str(a.timestamp),
                "description": a.description
            })

    external_intel: Dict[str, Any] = {"nvd": [], "cisa_kev": []}
    fake_cves: List[str] = []

    for cve in extracted["cves"]:
        if is_probably_fake_cve(cve):
            fake_cves.append(cve)
            continue

        nvd_data = await intel_sources.fetch_nvd_cve(cve)
        kev_data = await intel_sources.fetch_cisa_kev(cve)

        if nvd_data:
            external_intel["nvd"].append(nvd_data)

        if kev_data and isinstance(kev_data, dict) and kev_data.get("cve_id"):
            external_intel["cisa_kev"].append(kev_data)

    try:
        external_intel["otx"] = await intel_sources.fetch_otx_pulses(query, limit=5)
    except Exception:
        external_intel["otx"] = []

    # MITRE offline mapping (group/alias)
    mitre_mapping: List[str] = []
    try:
        mitre_mapping = mitre_service.build_mitre_mapping_for_query(query)
    except Exception:
        mitre_mapping = []

    # MITRE unified search
    mitre_match: Dict[str, Any] = {"matched": False}
    try:
        mitre_match = mitre_service.search_any(query)
    except Exception:
        mitre_match = {"matched": False}

    recommended_actions = []
    if len(mitre_mapping) > 0:
        recommended_actions = [
            "Review endpoint telemetry for techniques mapped to this group/technique",
            "Hunt for suspicious PowerShell / script execution and persistence indicators",
            "Check firewall/proxy logs for outbound C2 patterns",
            "Validate alerting coverage against MITRE techniques"
        ]
    elif len(extracted.get("cves", [])) > 0:
        recommended_actions = [
            "Validate vulnerable assets and patch affected systems",
            "Check WAF/IDS logs for exploit attempts",
            "Monitor for post-exploitation behavior (new users, persistence, lateral movement)"
        ]

    ai_summary_raw = await ai_service.summarize_threat_intel(
        query=query,
        extracted_iocs=extracted,
        correlated_alerts=correlated,
        external_intel=external_intel
    )

    ai_summary = ai_summary_raw

    return {
        "query": query,
        "extracted_iocs": extracted,
        "correlated_alerts": correlated,
        "external_intel": external_intel,
        "ai_summary": ai_summary.strip(),
        "mitre_mapping": mitre_mapping,
        "recommended_actions": recommended_actions
    }
