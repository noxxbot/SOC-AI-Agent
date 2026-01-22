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

    # ======================================================
    # (A) Unsafe Request -> Guardrail Block
    # ======================================================
    if qtype == "unsafe_request":
        return {
            "query": query,
            "extracted_iocs": {"cves": [], "ips": [], "domains": [], "sha256": [], "md5": []},
            "correlated_alerts": [],
            "external_intel": {"nvd": [], "cisa_kev": []},
            "ai_summary": ai_service.cyber_guardrail_response(query),
            "mitre_mapping": [],
            "recommended_actions": []
        }

    # ======================================================
    # (B) Out of scope -> Refuse & redirect
    # ======================================================
    if qtype == "out_of_scope":
        return {
            "query": query,
            "extracted_iocs": {"cves": [], "ips": [], "domains": [], "sha256": [], "md5": []},
            "correlated_alerts": [],
            "external_intel": {"nvd": [], "cisa_kev": []},
            "ai_summary": ai_service.out_of_scope_response(query),
            "mitre_mapping": [],
            "recommended_actions": []
        }

    # ======================================================
    # (C) MITRE Query -> Offline MITRE Search
    # ======================================================
    if qtype == "mitre_query":
        mitre_match: Dict[str, Any] = {"matched": False}
        mitre_mapping: List[str] = []

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

        ai_summary = (
            "✅ MITRE ATT&CK Offline Match Found.\n\n"
            f"Query: {query}\n\n"
            f"Match Type: {mitre_match.get('match_type')}\n\n"
            "Details:\n"
            f"{json.dumps(mitre_match, indent=2)}"
        )

        return {
            "query": query,
            "extracted_iocs": {"cves": [], "ips": [], "domains": [], "sha256": [], "md5": []},
            "correlated_alerts": [],
            "external_intel": {"nvd": [], "cisa_kev": []},
            "ai_summary": ai_summary.strip(),
            "mitre_mapping": mitre_mapping,
            "recommended_actions": [
                "Use this MITRE technique/tactic to build SIEM detections",
                "Map this to endpoint telemetry (Sysmon/EDR)",
                "Create a hunt query and response playbook"
            ]
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

        ai_summary = await ai_service.answer_cybersecurity_question(query, context=context)

        return {
            "query": query,
            "extracted_iocs": {"cves": [], "ips": [], "domains": [], "sha256": [], "md5": []},
            "correlated_alerts": [],
            "external_intel": {"nvd": [], "cisa_kev": []},
            "ai_summary": ai_summary.strip(),
            "mitre_mapping": [],
            "recommended_actions": [
                "Validate this using SIEM/EDR telemetry",
                "Add detection logic based on MITRE ATT&CK ideas",
                "Document a response checklist for SOC"
            ]
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

    # SOC-ready summary (safe rules)
    prompt = f"""
You are a SOC Threat Intel Correlation Analyst.

STRICT RULES:
- Only use the data provided below.
- If external intel is empty, clearly say: "No public intel found".
- Do NOT claim KEV exploited if it is not explicitly present.
- Do NOT make up CVSS, vendor, exploit details.
- If MITRE mapping exists, mention it as "MITRE ATT&CK reference".

User Query:
{query}

Extracted IOCs:
{json.dumps(extracted, indent=2)}

Correlated Alerts from SOC DB:
{json.dumps(correlated, indent=2)}

External Intel Data:
{json.dumps(external_intel, indent=2)}

MITRE Match (Offline):
{json.dumps(mitre_match, indent=2)}

MITRE Mapping (Offline):
{json.dumps(mitre_mapping, indent=2)}

Write a short SOC-ready summary:
- What is it?
- What evidence do we have internally?
- What does external intel confirm?
- What does MITRE mapping suggest (if available)?
- What should the analyst do next?
"""

    ai_summary = await ai_service._ask_ollama(prompt)

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

    return {
        "query": query,
        "extracted_iocs": extracted,
        "correlated_alerts": correlated,
        "external_intel": external_intel,
        "ai_summary": ai_summary.strip(),
        "mitre_mapping": mitre_mapping,
        "recommended_actions": recommended_actions
    }
