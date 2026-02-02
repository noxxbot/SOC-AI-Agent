import os
import json
import re
import asyncio
import httpx
import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from app.core.config import settings


class AIService:
    def __init__(self):
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "llama3:8b")
        self.logger = logging.getLogger(__name__)

    async def _ask_ollama(self, prompt: str) -> str:
        url = f"{self.ollama_url}/api/generate"

        payload = {
            "model": settings.OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0,
                "top_p": 0.1,
                "repeat_penalty": 1.1
            }
        }

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")

    async def check_ollama_ready(self) -> bool:
        url = f"{self.ollama_url}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url)
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            self.logger.error(f"Ollama ping failed at {url}: {exc}")
            return False
        models = payload.get("models") or []
        names = [str(m.get("name") or "") for m in models if isinstance(m, dict)]
        self.logger.info(f"Ollama models available: {names}")
        if self.model not in names:
            self.logger.error(f"Ollama model not found: {self.model}. Available: {names}")
            return False
        return True

    # =========================================================
    # Phase 3: LLM Output Cleaning / Safety
    # =========================================================
    def _clean_llm_output(self, text: str) -> str:
        """
        Cleans LLM output so it can be parsed as JSON.
        Removes markdown code blocks like ```json ... ```
        """
        if not text:
            return ""

        cleaned = text.strip()
        cleaned = cleaned.replace("```json", "").replace("```JSON", "")
        cleaned = cleaned.replace("```", "").strip()

        return cleaned

    def _extract_json_from_text(self, text: str):
        import re
        import json
        try:
            return json.loads(text)
        except Exception:
            pass
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except Exception:
                return None
        return None

    def _normalize_bool(self, value: Any) -> bool:
        """
        Converts 0/1, "true"/"false", True/False into strict boolean.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            v = value.strip().lower()
            if v in ["true", "yes", "1"]:
                return True
            if v in ["false", "no", "0"]:
                return False
        return False

    def _normalize_threat_vectors(self, tv: Any) -> Dict[str, bool]:
        """
        threatVectors must always be a dictionary with required keys:
        persistence, lateralMovement, exfiltration, reconnaissance, credentialAccess
        """
        default_tv = {
            "persistence": False,
            "lateralMovement": False,
            "exfiltration": False,
            "reconnaissance": False,
            "credentialAccess": False
        }

        # If model gives list like ["Brute Force", "Credential Stuffing"]
        if isinstance(tv, list):
            joined = " ".join([str(x).lower() for x in tv])

            if "credential" in joined or "stuffing" in joined or "brute" in joined:
                default_tv["credentialAccess"] = True
            if "recon" in joined or "scan" in joined:
                default_tv["reconnaissance"] = True
            if "exfil" in joined:
                default_tv["exfiltration"] = True
            if "lateral" in joined:
                default_tv["lateralMovement"] = True
            if "persist" in joined:
                default_tv["persistence"] = True

            return default_tv

        # If model gives weird object like {"primary": "...", "secondary":[...]}
        if isinstance(tv, dict) and ("primary" in tv or "secondary" in tv):
            sec = tv.get("secondary", [])
            pri = tv.get("primary", "")
            combined = [pri]
            if isinstance(sec, list):
                combined += sec
            else:
                combined.append(sec)
            return self._normalize_threat_vectors(combined)

        # If model gives dict like {"persistence": 0, "reconnaissance": 1}
        if isinstance(tv, dict):
            for k in default_tv.keys():
                if k in tv:
                    default_tv[k] = self._normalize_bool(tv[k])
            return default_tv

        return default_tv

    def _safe_default_analysis(self, alert: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        alert_id = None
        if isinstance(alert, dict):
            alert_id = alert.get("id") or alert.get("alert_id")
        self.logger.warning("AI fail-closed fallback triggered", extra={"alert_id": alert_id})
        return {
            "summary": "AI failed – manual review needed.",
            "case_notes": "AI failed – manual review needed.",
            "explainability": ["AI failure — no reliable analysis"],
            "assessment": {
                "is_incident": False,
                "incident_severity": "none",
                "confidence_score": 0,
                "reasoning": "AI investigation failed or returned invalid output"
            },
            "recommended_actions": [],
            "ioc_analysis": {
                "observed_iocs": [],
                "ioc_verdict": "unknown",
                "ioc_notes": "AI investigation failed or returned invalid output"
            },
            "mitre_analysis": {
                "techniques": [],
                "tactics": [],
                "mitre_notes": "AI investigation failed or returned invalid output"
            },
            "timeline": ["Step 1: AI investigation failed before a conclusion was reached."],
            "mitre_mapping": [],
            "ioc_verdicts": [],
            "confidence_score": 0,
            "is_incident": False,
            "incident_severity": "none",
            "confidence_breakdown": {},
            "status": "failed",
            "error_message": "ai_failure",
            "error": "ai_failure"
        }

    def _safe_default_log_analysis(self, explanation: str, manual_override: bool = False) -> Dict[str, Any]:
        """
        This fallback must never trigger alerts or incidents.
        It exists only to provide safe defaults in manual workflows.
        """
        if manual_override is not True:
            self.logger.warning("SAFE DEFAULT ANALYSIS USED - FAIL CLOSED", extra={"manual_override": False})
        else:
            self.logger.warning("SAFE DEFAULT ANALYSIS USED - FAIL CLOSED", extra={"manual_override": True})
        return {
            "riskScore": 0,
            "threatDetected": False,
            "severity": "low",
            "should_alert": False,
            "should_incident": False,
            "analysis_source": "safe_default_fallback",
            "fail_closed": True,
            "explanation": explanation,
            "recommendations": [],
            "threatVectors": {
                "persistence": False,
                "lateralMovement": False,
                "exfiltration": False,
                "reconnaissance": False,
                "credentialAccess": False
            }
        }

    def _fix_explanation_if_json(self, explanation: Any) -> str:
        """
        Sometimes LLM returns JSON inside explanation.
        We force it into clean SOC text.
        """
        if explanation is None:
            return "Suspicious activity detected based on log patterns."

        explanation_text = str(explanation).strip()

        # If explanation looks like JSON or contains JSON keys, replace it
        if (
            explanation_text.startswith("{")
            or '"riskScore"' in explanation_text
            or '"threatDetected"' in explanation_text
            or '"recommendations"' in explanation_text
            or '"threatVectors"' in explanation_text
        ):
            return "Suspicious activity detected based on log patterns (LLM output was malformed)."

        return explanation_text

    def _word_count(self, text: str) -> int:
        return len([w for w in re.split(r"\s+", text or "") if w.strip()])

    def _coerce_list(self, value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        if value is None:
            return []
        value = str(value).strip()
        return [value] if value else []

    def _normalize_risk_level(self, value: Any) -> str:
        level = str(value or "low").strip().lower()
        if level not in {"low", "medium", "high", "critical"}:
            return "low"
        return level

    def _derive_log_signals(self, log: Dict[str, Any]) -> Dict[str, Any]:
        fields = log.get("fields") or {}
        tags = log.get("tags") or []
        mitre_matches = fields.get("mitre_matches") or log.get("mitre_matches") or []
        ioc_intel = fields.get("ioc_intel") or log.get("ioc_intel") or {}
        ioc_summary = ioc_intel.get("ioc_summary") or {}
        ioc_matches = ioc_intel.get("ioc_matches") or []
        ioc_risk = str(ioc_summary.get("risk") or "unknown").lower()
        try:
            ioc_confidence = int(ioc_summary.get("confidence") or 0)
        except Exception:
            ioc_confidence = 0
        allowlist_benign = ioc_risk == "benign"
        if ioc_matches:
            verdicts = [str(m.get("verdict") or "").lower() for m in ioc_matches]
            if verdicts and all(v == "benign" for v in verdicts):
                allowlist_benign = True

        suspicious_tag_set = {
            "powershell",
            "encoded_command",
            "rundll32",
            "regsvr32",
            "certutil",
            "wmic",
            "schtasks"
        }
        suspicious_tags = []
        for tag in tags:
            tag_value = str(tag or "").strip().lower()
            if not tag_value:
                continue
            if tag_value in suspicious_tag_set or tag_value.startswith("mitre:") or tag_value.startswith("ioc:"):
                suspicious_tags.append(tag_value)

        try:
            severity_score = int(log.get("severity_score") or 0)
        except Exception:
            severity_score = 0

        mitre_ids = []
        for match in mitre_matches:
            if not isinstance(match, dict):
                continue
            tid = str(match.get("technique_id") or match.get("id") or "").strip()
            name = str(match.get("technique_name") or match.get("name") or "").strip()
            if tid:
                mitre_ids.append({"technique_id": tid, "name": name})

        return {
            "severity_score": severity_score,
            "mitre_matches": mitre_matches,
            "mitre_ids": mitre_ids,
            "ioc_intel": ioc_intel,
            "ioc_summary": ioc_summary,
            "ioc_matches": ioc_matches,
            "ioc_risk": ioc_risk,
            "ioc_confidence": ioc_confidence,
            "allowlist_benign": allowlist_benign,
            "suspicious_tags": suspicious_tags
        }

    def _score_log_confidence(self, signals: Dict[str, Any]) -> int:
        severity_score = int(signals.get("severity_score") or 0)
        ioc_risk = str(signals.get("ioc_risk") or "unknown").lower()
        mitre_matches = signals.get("mitre_matches") or []
        suspicious_tags = signals.get("suspicious_tags") or []
        allowlist_benign = bool(signals.get("allowlist_benign"))

        score = 15
        if severity_score >= 60:
            score += 20
        if severity_score >= 80:
            score += 15
        if mitre_matches:
            score += 20
        if ioc_risk in {"suspicious", "malicious"}:
            score += 25
        if suspicious_tags:
            score += 10
        if ioc_risk == "malicious":
            score += 10

        major = 0
        if severity_score >= 80:
            major += 1
        if mitre_matches:
            major += 1
        if ioc_risk in {"suspicious", "malicious"}:
            major += 1

        if allowlist_benign:
            score = min(score, 30)
        if major < 2 and score > 75:
            score = 70
        if not (mitre_matches or ioc_risk in {"suspicious", "malicious"} or severity_score >= 60 or suspicious_tags):
            score = min(score, 40)

        return int(max(0, min(100, score)))

    def _risk_level_from_score(self, score: int, signals: Dict[str, Any]) -> str:
        if signals.get("allowlist_benign"):
            return "low"
        ioc_risk = str(signals.get("ioc_risk") or "unknown").lower()
        severity_score = int(signals.get("severity_score") or 0)
        if ioc_risk == "malicious" and score >= 85:
            return "critical"
        if score >= 85 or severity_score >= 90:
            return "high"
        if score >= 55 or severity_score >= 60:
            return "medium"
        return "low"

    def _build_explainability(self, log: Dict[str, Any], signals: Dict[str, Any]) -> List[str]:
        items: List[str] = []
        severity_score = int(signals.get("severity_score") or 0)
        ioc_risk = str(signals.get("ioc_risk") or "unknown").lower()
        ioc_confidence = int(signals.get("ioc_confidence") or 0)
        suspicious_tags = signals.get("suspicious_tags") or []
        mitre_ids = signals.get("mitre_ids") or []
        allowlist_benign = bool(signals.get("allowlist_benign"))

        if severity_score >= 60:
            items.append(f"Severity score {severity_score} indicates elevated risk")
        if mitre_ids:
            for match in mitre_ids[:3]:
                tid = match.get("technique_id")
                name = match.get("name")
                if name:
                    items.append(f"Matched MITRE technique {tid} {name}")
                else:
                    items.append(f"Matched MITRE technique {tid}")
        if "encoded_command" in suspicious_tags:
            items.append("PowerShell execution with encoded command detected (tag: encoded_command)")
        if "powershell" in suspicious_tags and "encoded_command" not in suspicious_tags:
            items.append("PowerShell execution observed (tag: powershell)")
        for tag in ["rundll32", "regsvr32", "certutil", "wmic", "schtasks"]:
            if tag in suspicious_tags:
                items.append(f"Living-off-the-land binary usage observed (tag: {tag})")
        if ioc_risk in {"suspicious", "malicious"}:
            items.append(f"IOC intel risk is {ioc_risk} (confidence {ioc_confidence})")
        if allowlist_benign:
            items.append("IOC matched offline allowlist and is considered benign")
        if not items:
            items.append("No strong suspicious indicators observed in available fields")

        return items

    def _build_recommended_actions(self, log: Dict[str, Any], signals: Dict[str, Any]) -> List[str]:
        if signals.get("allowlist_benign"):
            return ["No action required (benign indicator confirmed)"]

        actions: List[str] = []
        tags = signals.get("suspicious_tags") or []
        event_type = str(log.get("event_type") or "").lower()
        category = str(log.get("category") or "").lower()
        ioc_risk = str(signals.get("ioc_risk") or "unknown").lower()

        if "encoded_command" in tags or "powershell" in tags:
            actions.extend([
                "Review process ancestry and parent-child relationships",
                "Check command line arguments and script content",
                "Collect Sysmon EventID 1 and Windows 4688 for validation"
            ])
        if event_type in {"login_failed", "failed_login"} or "login_failed" in event_type or category in {"auth", "authentication"}:
            actions.extend([
                "Review failed login trends for the user and source",
                "Block the source IP if confirmed malicious",
                "Enforce or verify MFA for the affected account"
            ])
        if "dns" in event_type or event_type == "dns_query" or category == "network":
            actions.extend([
                "Check DNS logs for repetition and additional queries",
                "Review outbound connections to the resolved destination",
                "Consider sinkholing or blocking the domain if confirmed suspicious"
            ])
        if ioc_risk in {"suspicious", "malicious"}:
            actions.extend([
                "Block the suspicious indicator in perimeter controls",
                "Hunt for related activity across endpoints"
            ])

        if not actions:
            actions.extend([
                "Collect additional endpoint telemetry around the event",
                "Validate user and host context for anomalies",
                "Monitor for follow-on activity tied to the same agent or host"
            ])

        unique_actions = []
        seen = set()
        for action in actions:
            if action not in seen:
                seen.add(action)
                unique_actions.append(action)
        return unique_actions[:6]

    def _fallback_case_notes(self, log: Dict[str, Any], explainability: List[str], risk_level: str) -> str:
        timestamp = str(log.get("timestamp") or "unknown time")
        agent_id = str(log.get("agent_id") or "unknown agent")
        hostname = str(log.get("hostname") or "unknown host")
        event_type = str(log.get("event_type") or "unknown event")
        category = str(log.get("category") or "other")
        message = str(log.get("message") or "").strip()
        iocs = log.get("iocs") or {}
        ioc_values = []
        for key in ["ips", "domains", "sha256", "md5", "cves"]:
            values = iocs.get(key) or []
            for val in values[:3]:
                ioc_values.append(str(val))
        ioc_text = ", ".join(ioc_values) if ioc_values else "no confirmed indicators"
        mitre_matches = (log.get("fields") or {}).get("mitre_matches") or log.get("mitre_matches") or []
        mitre_text = ", ".join([str(m.get("technique_id") or "") for m in mitre_matches if isinstance(m, dict)]) or "no MITRE techniques observed"

        sentences = [
            f"At {timestamp}, agent {agent_id} on host {hostname} reported a {event_type} event in the {category} category.",
            f"Observed message context includes: {message}" if message else "Observed message context was limited to the available log fields.",
            f"IOC extraction yielded {ioc_text}, and MITRE mapping shows {mitre_text}.",
            f"The current risk level is assessed as {risk_level} based on the evidence captured in this log.",
            "This assessment is derived strictly from available fields and does not assume additional activity beyond the recorded event.",
        ]
        if explainability:
            sentences.append("Key reasons include: " + "; ".join(explainability[:4]) + ".")

        text = " ".join(sentences)
        while self._word_count(text) < 80:
            text = text + " Additional telemetry, process lineage, and adjacent network events should be reviewed to confirm scope and intent without assuming maliciousness."
        words = self._word_count(text)
        if words > 180:
            parts = text.split()
            text = " ".join(parts[:180])
        return text

    def build_log_notes_prompt(self, log: Dict[str, Any]) -> str:
        return f"""
You are a SOC analyst writing auto case notes for a single log record.

STRICT RULES:
- Use only the data provided.
- Do not invent facts or outcomes.
- Be defensive and blue-team only.
- Treat allowlisted IOCs as benign.
- Return ONLY valid JSON with the exact schema.
- case_notes must be 80 to 180 words.

Required JSON schema:
{{
  "case_notes": "string",
  "risk_level": "low|medium|high|critical",
  "confidence_score": 0,
  "explainability": ["string"],
  "recommended_actions": ["string"]
}}

Log Context:
{json.dumps(log, indent=2)}
"""

    async def generate_log_notes(self, log: Dict[str, Any]) -> Dict[str, Any]:
        signals = self._derive_log_signals(log or {})
        derived_confidence = self._score_log_confidence(signals)
        derived_risk = self._risk_level_from_score(derived_confidence, signals)
        derived_explainability = self._build_explainability(log or {}, signals)
        derived_actions = self._build_recommended_actions(log or {}, signals)

        prompt = self.build_log_notes_prompt(log or {})
        raw_output = ""
        try:
            raw_output = await self._ask_ollama(prompt)
        except Exception:
            fallback_notes = self._fallback_case_notes(log or {}, derived_explainability, derived_risk)
            return {
                "case_notes": fallback_notes,
                "risk_level": derived_risk,
                "confidence_score": derived_confidence,
                "explainability": derived_explainability,
                "recommended_actions": derived_actions,
                "error": "LLM unavailable"
            }

        self.logger.info("AI raw output", extra={"raw_output": raw_output})
        cleaned = self._clean_llm_output(raw_output)
        parsed = self._extract_json_from_text(cleaned) or {}

        case_notes = str(parsed.get("case_notes") or "").strip()
        explainability = self._coerce_list(parsed.get("explainability"))
        recommended_actions = self._coerce_list(parsed.get("recommended_actions"))

        if not explainability:
            explainability = derived_explainability
        else:
            combined = derived_explainability + explainability
            explainability = []
            seen = set()
            for item in combined:
                if item not in seen and item:
                    seen.add(item)
                    explainability.append(item)
            explainability = explainability[:6]

        if not recommended_actions:
            recommended_actions = derived_actions
        else:
            combined = derived_actions + recommended_actions
            recommended_actions = []
            seen = set()
            for item in combined:
                if item not in seen and item:
                    seen.add(item)
                    recommended_actions.append(item)
            if signals.get("allowlist_benign"):
                recommended_actions = ["No action required (benign indicator confirmed)"]
            else:
                recommended_actions = recommended_actions[:6]

        if self._word_count(case_notes) < 80 or self._word_count(case_notes) > 180:
            case_notes = self._fallback_case_notes(log or {}, explainability, derived_risk)

        return {
            "case_notes": case_notes,
            "risk_level": derived_risk,
            "confidence_score": derived_confidence,
            "explainability": explainability,
            "recommended_actions": recommended_actions
        }

    # =========================================================
    # Phase 3: Threat Intel Summary Helper (KEEP WORKING)
    # =========================================================
    def _looks_like_fake_or_invalid_query(self, query: str) -> bool:
        """
        Basic heuristic: if query contains CVE-9999-99999 or weird pattern.
        This is only used to adjust the LLM tone.
        """
        q = (query or "").strip().upper()

        # obvious fake CVE
        if "CVE-9999-" in q:
            return True

        # too short / meaningless
        if len(q.strip()) < 3:
            return True

        return False

    async def summarize_threat_intel(
        self,
        query: str,
        extracted_iocs: Dict[str, Any],
        correlated_alerts: List[Dict[str, Any]],
        external_intel: Dict[str, Any],
        max_words: int = 180
    ) -> str:
        """
        Phase 3: SOC-ready summary generator for Threat Intel Correlation endpoint.
        - Avoids hallucinations
        - Negative / warning response for fake or irrelevant queries
        - Uses only provided data
        """

        # Safe defaults
        extracted_iocs = extracted_iocs or {}
        correlated_alerts = correlated_alerts or []
        external_intel = external_intel or {"nvd": [], "cisa_kev": [], "otx": []}

        # Determine if we have any real intel
        nvd_count = len(external_intel.get("nvd", []) or [])
        kev_count = len(external_intel.get("cisa_kev", []) or [])
        otx_count = len(external_intel.get("otx", []) or [])
        corr_count = len(correlated_alerts)

        fake_query = self._looks_like_fake_or_invalid_query(query)
        ip_list = extracted_iocs.get("ips", []) or []
        public_dns_ips = {"8.8.8.8", "1.1.1.1", "9.9.9.9"}
        non_ip_ioc_count = (
            len(extracted_iocs.get("cves", []) or [])
            + len(extracted_iocs.get("domains", []) or [])
            + len(extracted_iocs.get("sha256", []) or [])
            + len(extracted_iocs.get("md5", []) or [])
        )
        is_ip_only = len(ip_list) > 0 and non_ip_ioc_count == 0

        # If nothing exists anywhere -> return a strict negative summary WITHOUT LLM
        if corr_count == 0 and nvd_count == 0 and kev_count == 0 and otx_count == 0:
            note = ""
            if fake_query:
                note = "\n\nNote: The query appears invalid or unverified."
            if is_ip_only:
                note += "\n\nNote: The IP appears commonly benign unless context suggests abuse."
                if any(ip in public_dns_ips for ip in ip_list):
                    note += (
                        "\n\nContext: This IP is a public DNS resolver. It is typically benign unless you see "
                        "abnormal DNS volume, unusual destination ports, tunneling patterns, or suspicious domains."
                    )
            return (
                "⚠️ No reliable correlation found.\n\n"
                f"Query: {query}\n"
                "Result: No matching alerts in SOC DB + no external intel matches.\n\n"
                "Next steps:\n"
                "- Verify the query (try a real CVE like CVE-2021-44228)\n"
                "- Try searching with an IP/domain/hash from your alert logs\n"
                "- Ensure your agents are generating alerts for this activity"
            ).strip() + note

        tone_note = ""
        if fake_query:
            tone_note = (
                "IMPORTANT: The query appears suspicious or invalid. "
                "Do not treat it as confirmed vulnerability intel unless external sources confirm it."
            )

        prompt = f"""
You are a SOC Threat Intel Correlation Analyst.

STRICT RULES:
- ONLY use the data given below.
- Do NOT assume an IOC is malicious without evidence.
- Some IOCs are commonly benign (e.g., 8.8.8.8, 1.1.1.1, 9.9.9.9) unless context shows abuse.
- If query is a public DNS IP, explain it is likely benign unless abnormal context exists and ask what context triggered the investigation.
- Only claim maliciousness if correlated alerts or external intel confirm it.
- If external intel is empty, say "No public intel found".
- Do NOT invent CVSS, exploited status, vendor/product, or attack details.
- If query looks invalid/fake, warn the analyst clearly.
- Do NOT include UI titles like "Sentinel Intelligence Report" or query type labels.
- Output must be clean markdown text only (no code fences, no JSON).
- Max words: {max_words}

{tone_note}

User Query:
{query}

Extracted IOCs:
{json.dumps(extracted_iocs, indent=2)}

Correlated Alerts (SOC DB):
{json.dumps(correlated_alerts, indent=2)}

External Intel:
{json.dumps(external_intel, indent=2)}

Response format:
Short Answer:
(2–5 lines)

What is it?:
Internal Evidence:
External Intel Confirmation:
Likely Verdict (benign/suspicious/unknown + confidence):
Next Steps:
"""

        try:
            out = await self._ask_ollama(prompt)
            return self._clean_llm_output(out).strip()
        except Exception:
            return (
                "⚠️ Summary generation failed due to AI service unavailability.\n\n"
                f"Query: {query}\n"
                f"Internal alerts: {corr_count}\n"
                f"External intel: NVD={nvd_count}, KEV={kev_count}, OTX={otx_count}\n"
                "Next steps:\n"
                "- Review internal alerts for context\n"
                "- Re-try external intel lookups later\n"
                "- Add detections for related IOCs"
            ).strip()

    # =========================================================
    # Phase 5 Step 1: Query Classification using AI (NEW)
    # (NO keyword list based detection)
    # =========================================================
    async def classify_query_type(self, query: str) -> Dict[str, Any]:
        """
        Classifies user query into:
        - ioc_query (CVE/IP/domain/hash)
        - mitre_query (Txxxx / technique / tactic / group)
        - analyst_question (general cybersecurity question)
        - out_of_scope (non-cyber or unrelated)
        - unsafe_request (hacking / illegal / malicious)
        Returns strict JSON.
        """
        query = (query or "").strip()
        if not query:
            return {"type": "out_of_scope", "reason": "Empty query"}

        prompt = f"""
You are a strict cybersecurity query classifier.

Task:
Classify the user query into one of these types:
- ioc_query
- mitre_query
- analyst_question
- out_of_scope
- unsafe_request

Rules:
- ioc_query: contains CVE, IP, domain, hash, IOC indicators.
- mitre_query: MITRE ATT&CK group/alias, technique ID (T1055), tactic names, technique names.
- analyst_question: defensive cybersecurity learning / detection / response questions.
- unsafe_request: requests for hacking, exploitation steps, malware creation, bypassing security, illegal actions.
- out_of_scope: not cybersecurity related.

Return ONLY valid JSON:
{{
  "type": "one_of_the_types",
  "reason": "short reason"
}}

User Query:
{query}
"""

        try:
            raw = await self._ask_ollama(prompt)
        except Exception:
            return {"type": "analyst_question", "reason": "LLM unavailable; fallback to analyst_question"}

        self.logger.info("AI raw output", extra={"raw_output": raw})
        cleaned = self._clean_llm_output(raw)
        parsed = self._extract_json_from_text(cleaned)
        if not parsed:
            self.logger.warning("AI returned non-JSON output", extra={"raw": raw})
            return {"type": "analyst_question", "reason": "Classifier JSON failed; fallback to analyst_question"}
        qtype = str(parsed.get("type", "")).strip()
        reason = str(parsed.get("reason", "")).strip()

        allowed = {"ioc_query", "mitre_query", "analyst_question", "out_of_scope", "unsafe_request"}
        if qtype not in allowed:
            return {"type": "analyst_question", "reason": "Classifier returned invalid type"}

        return {"type": qtype, "reason": reason or "Classified successfully"}

    # =========================================================
    # Phase 5 Step 3: Cybersecurity Guardrail (NEW)
    # - Block offensive/hacking instructions
    # - Allow only defensive/SOC guidance
    # =========================================================
    def _guardrail_refusal(self, query: str) -> str:
        """
        Safe refusal response with defensive alternatives.
        """
        return (
            "🚫 I can’t help with hacking, exploitation, bypassing security, or malware creation.\n\n"
            f"Your query: {query}\n\n"
            "✅ But I *can* help you defensively (SOC/Blue-Team), for example:\n"
            "- How to detect this attack in logs (Windows/Sysmon/SIEM)\n"
            "- How to mitigate and harden systems\n"
            "- Incident response steps\n"
            "- MITRE ATT&CK mapping and detection ideas\n"
        ).strip()

    def cyber_guardrail_response(self, query: str) -> str:
        return self._guardrail_refusal(query)

    def out_of_scope_response(self, query: str) -> str:
        """
        If query is not cyber-related.
        """
        return (
            "⚠️ Out of scope.\n\n"
            "This page only answers Cybersecurity / SOC / Threat Intel related queries.\n\n"
            f"Your query: {query}\n\n"
            "Examples you can ask:\n"
            "- What is an APT group?\n"
            "- What is lateral movement?\n"
            "- Explain persistence on Windows\n"
            "- T1055\n"
            "- CVE-2021-44228\n"
        ).strip()

    async def answer_cybersecurity_question(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
        max_words: int = 260
    ) -> str:
        """
        Phase 5: answers cybersecurity analyst questions in a safe way.
        - small question -> small answer
        - complex question -> detailed answer
        - no hallucination
        - guardrail blocks offensive requests
        """
        context = context or {}

        prompt = f"""
You are a Senior SOC Analyst and Cybersecurity Expert.

User Question:
{query}

STRICT RULES:
- Answer only in cybersecurity / blue-team / defensive context.
- Assume the question is cybersecurity-related and answer it directly.
- DO NOT provide hacking steps, exploitation instructions, payloads, malware creation, or bypass methods.
- If the user asks for offensive steps, refuse and provide defensive alternatives only.
- Prefer medium-to-detailed answers by default. Only keep it short if the user asks for a short answer.
- If the query includes how/steps/process/procedure/investigate/workflow/triage/playbook, always respond in steps.
- If the user asks to explain multiple items (OSI layers, CIA triad, TCP handshake), provide a structured breakdown (table or bullets).
- Let the intent and context decide which sections to include.
- Do NOT include "Sentinel Intelligence Report" or any A/B/C query labels.
- Output must be clean markdown text only (no code fences, no JSON).
- Do NOT hallucinate or make up facts.
- If not enough info, say: "Not enough data to confirm." and suggest logs/telemetry to check.
- Keep answer under {max_words} words.
- Special case: if the query is an IP like 8.8.8.8, 1.1.1.1, or 9.9.9.9, state it is a public DNS service and only suspicious in abnormal context.

Helpful Context (may be empty):
{json.dumps(context, indent=2)}

Output format rules (always start with Short Answer):
Short Answer:
(2–5 lines)

Then choose ONLY the sections that fit the question:

If informational / educational:
Detailed Explanation:
Key Points:
Example:

If how-to / steps / investigation:
Step-by-step Answer:
Common Mistakes:
Practical Checklist:

If comparison:
Comparison:
(table format)

If broad:
Summary Checklist:

Actions:
- If purely informational: "No action required (informational query)"
- If incident-like: list 3–6 real SOC actions
"""

        try:
            out = await self._ask_ollama(prompt)
            return self._clean_llm_output(out).strip()
        except Exception:
            return (
                "Short Answer: Not enough data to provide an AI-generated response right now.\n"
                "Detection Ideas:\n"
                "- Check relevant Windows/Linux logs for suspicious events\n"
                "- Correlate with SIEM alerts and endpoint telemetry\n"
                "Mitigation / Response:\n"
                "- Apply least privilege and hardening controls\n"
                "- Validate network segmentation and access controls"
            ).strip()

    # =========================================================
    # Existing: Log Analysis (KEEP WORKING)
    # =========================================================
    async def analyze_security_logs(self, logs: str) -> Dict[str, Any]:
        """
        Analyze logs and return structured SOC analysis
        in schema expected by /api/v1/analyze endpoint.
        """
        prompt = f"""
You are a SOC analyst.

Analyze the following logs and return ONLY valid JSON.
DO NOT add markdown, DO NOT add explanation outside JSON.

Required JSON schema (keys must match exactly):
{{
  "riskScore": 0,
  "threatDetected": false,
  "explanation": "string",
  "recommendations": ["string"],
  "threatVectors": {{
    "persistence": false,
    "lateralMovement": false,
    "exfiltration": false,
    "reconnaissance": false,
    "credentialAccess": false
  }}
}}

Rules:
- riskScore must be between 0 and 100
- threatDetected must be true/false
- explanation must be plain text (NOT JSON inside)
- recommendations must be a list of steps
- threatVectors must be a dictionary with ONLY boolean values

Logs:
{logs}
"""

        raw_output = await self._ask_ollama(prompt)
        self.logger.info("AI raw output", extra={"raw_output": raw_output})
        cleaned = self._clean_llm_output(raw_output)
        parsed = self._extract_json_from_text(cleaned)
        if not parsed:
            self.logger.warning("AI returned non-JSON output", extra={"raw": raw_output})
            return self._safe_default_log_analysis(raw_output, manual_override=True)

        risk_score = parsed.get("riskScore", 50)
        threat_detected = parsed.get("threatDetected", True)
        explanation = parsed.get("explanation", "Suspicious activity detected based on log patterns.")
        explanation = self._fix_explanation_if_json(explanation)
        recommendations = parsed.get("recommendations", ["Review logs", "Investigate source"])
        threat_vectors = parsed.get("threatVectors", {})

        try:
            risk_score = int(risk_score)
        except Exception:
            risk_score = 50

        risk_score = int(max(0, min(100, risk_score)))
        threat_detected = self._normalize_bool(threat_detected)

        if not isinstance(recommendations, list):
            recommendations = [str(recommendations)]

        recommendations = [str(x) for x in recommendations if str(x).strip()]

        threat_vectors = self._normalize_threat_vectors(threat_vectors)

        return {
            "riskScore": risk_score,
            "threatDetected": threat_detected,
            "explanation": explanation,
            "recommendations": recommendations,
            "threatVectors": threat_vectors
        }

    async def _investigate_with_retry(
        self,
        prompt: str,
        alert: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], str, str, int, Optional[str]]:
        """
        Retry exists only to handle transient LLM failures.
        It must not override fail-closed logic.
        """
        max_retries = int(getattr(settings, "AI_MAX_RETRIES", 2) or 2)
        delay = int(getattr(settings, "AI_RETRY_DELAY_SECONDS", 2) or 2)
        max_retries = max(1, max_retries)
        retry_count = 0
        last_retry_reason = None
        alert_id = None
        if isinstance(alert, dict):
            alert_id = alert.get("id") or alert.get("alert_id")
        cleaned = ""
        raw_response = ""
        for attempt in range(max_retries):
            if attempt > 0:
                retry_count = attempt
            try:
                start = time.monotonic()
                raw_response = await self._ask_ollama(prompt)
                duration = time.monotonic() - start
                self.logger.info(f"AI CALL DURATION={duration:.2f}s", extra={"alert_id": alert_id})
                self.logger.info(f"RAW AI RESPONSE={raw_response}", extra={"alert_id": alert_id})
                self.logger.info("AI raw output", extra={"raw_output": raw_response})
                self.logger.warning("RAW LLM OUTPUT: %s", raw_response)
            except httpx.TimeoutException:
                last_retry_reason = "timeout"
                if attempt < max_retries - 1:
                    self.logger.warning(f"AI retry {attempt + 1}/{max_retries} due to timeout", extra={"alert_id": alert_id})
                    await asyncio.sleep(delay)
                    continue
                failure = self._safe_default_analysis(alert)
                failure["error_message"] = "retry_exhausted"
                return failure, "", raw_response, retry_count, last_retry_reason
            except httpx.ConnectError:
                last_retry_reason = "connection_error"
                if attempt < max_retries - 1:
                    self.logger.warning(f"AI retry {attempt + 1}/{max_retries} due to connection_error", extra={"alert_id": alert_id})
                    await asyncio.sleep(delay)
                    continue
                failure = self._safe_default_analysis(alert)
                failure["error_message"] = "retry_exhausted"
                return failure, "", raw_response, retry_count, last_retry_reason
            except Exception:
                failure = self._safe_default_analysis(alert)
                return failure, "", raw_response, retry_count, last_retry_reason

            cleaned = self._clean_llm_output(raw_response)
            if not str(cleaned or "").strip():
                last_retry_reason = "empty_response"
                if attempt < max_retries - 1:
                    self.logger.warning(f"AI retry {attempt + 1}/{max_retries} due to empty_response", extra={"alert_id": alert_id})
                    await asyncio.sleep(delay)
                    continue
                failure = self._safe_default_analysis(alert)
                failure["error_message"] = "retry_exhausted"
                return failure, cleaned or "", raw_response, retry_count, last_retry_reason
            parsed = self._extract_json_from_text(cleaned)
            if not parsed:
                last_retry_reason = "json_parse_error"
                self.logger.warning("AI returned non-JSON output", extra={"raw": raw_response})
                if attempt < max_retries - 1:
                    self.logger.warning(f"AI retry {attempt + 1}/{max_retries} due to json_parse_error", extra={"alert_id": alert_id})
                    await asyncio.sleep(delay)
                    continue
                fallback = {
                    "summary": "AI output invalid",
                    "is_incident": False,
                    "confidence_score": 0,
                    "incident_severity": "none",
                    "case_notes": "Model returned non-JSON output"
                }
                normalized = self._normalize_investigation(
                    fallback,
                    alert,
                    context,
                    error_message="json_parse_error"
                )
                return normalized, cleaned or "", raw_response, retry_count, last_retry_reason
            normalized = self._normalize_investigation(parsed, alert, context)
            return normalized, cleaned, raw_response, retry_count, last_retry_reason
        failure = self._safe_default_analysis(alert)
        failure["error_message"] = "retry_exhausted"
        return failure, cleaned, raw_response, retry_count, last_retry_reason

    # =========================================================
    # Existing: Alert Analysis (KEEP WORKING)
    # =========================================================
    async def analyze_alert_data(
        self,
        alert_context: Dict[str, Any],
        telemetry_context: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze alert + telemetry context for deeper investigation.
        Returns schema for /api/v1/ai/analyze-alert endpoint.
        """
        prompt = f"""
You are a SOC analyst.

Analyze this security alert and telemetry context.
Return ONLY valid JSON (no markdown, no extra text).

Required JSON schema (keys must match exactly):
{{
  "root_cause": "string",
  "mitre_mapping": ["string"],
  "confidence_score": 0,
  "response_actions": ["string"]
}}

Rules:
- confidence_score must be 0 to 100
- mitre_mapping should contain technique IDs if possible (ex: "T1110 Brute Force")
- response_actions must be safe, realistic remediation steps

Alert Context:
{json.dumps(alert_context, indent=2)}

Telemetry Context:
{json.dumps(telemetry_context, indent=2)}
"""

        raw_output = await self._ask_ollama(prompt)
        self.logger.info("AI raw output", extra={"raw_output": raw_output})
        cleaned = self._clean_llm_output(raw_output)
        parsed = self._extract_json_from_text(cleaned)
        if not parsed:
            self.logger.warning("AI returned non-JSON output", extra={"raw": raw_output})
            return {
                "root_cause": raw_output,
                "mitre_mapping": ["T1110 Brute Force"],
                "confidence_score": 70,
                "response_actions": [
                    "Investigate related authentication events",
                    "Enable MFA",
                    "Block suspicious IP",
                    "Monitor endpoint for persistence"
                ]
            }

        root_cause = str(parsed.get("root_cause", "Potential suspicious activity detected."))
        mitre_mapping = parsed.get("mitre_mapping", ["T1110 Brute Force"])
        confidence_score = parsed.get("confidence_score", 70)
        response_actions = parsed.get("response_actions", [
            "Investigate related authentication events",
            "Enable MFA",
            "Block suspicious IP",
            "Monitor endpoint for persistence"
        ])

        if not isinstance(mitre_mapping, list):
            mitre_mapping = [str(mitre_mapping)]
        mitre_mapping = [str(x) for x in mitre_mapping if str(x).strip()]

        try:
            confidence_score = int(confidence_score)
        except Exception:
            confidence_score = 70

        confidence_score = int(max(0, min(100, confidence_score)))

        if not isinstance(response_actions, list):
            response_actions = [str(response_actions)]
        response_actions = [str(x) for x in response_actions if str(x).strip()]

        return {
            "root_cause": root_cause,
            "mitre_mapping": mitre_mapping,
            "confidence_score": confidence_score,
            "response_actions": response_actions
        }

    def _extract_investigation_inputs(self, alert: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        alert = alert or {}
        context = context or {}
        extracted = {"ips": [], "domains": [], "sha256": [], "md5": [], "cves": []}
        mapped_ioc_intel: List[Dict[str, Any]] = []
        mitre_matches: List[Dict[str, Any]] = []

        def _extract_technique_id(value: Any) -> str:
            text = str(value or "").strip()
            if not text:
                return ""
            if text.lower().startswith("mitre:"):
                text = text.split(":", 1)[-1].strip()
            match = re.search(r"(T\d{4}(?:\.\d{3})?)", text, re.IGNORECASE)
            if match:
                return match.group(1).upper()
            token = text.split()[0].strip()
            return token.upper() if token else ""

        def _normalize_mitre_items(items: Any, tags: Any = None) -> List[Dict[str, Any]]:
            normalized: List[Dict[str, Any]] = []
            candidates: List[Any] = []
            if isinstance(items, list):
                candidates.extend(items)
            elif items:
                candidates.append(items)
            if isinstance(tags, list):
                for tag in tags:
                    tag_value = str(tag or "").strip()
                    if tag_value.lower().startswith("mitre:"):
                        candidates.append(tag_value.split(":", 1)[-1])
            for item in candidates:
                if isinstance(item, dict):
                    tid = item.get("technique_id") or item.get("id") or item.get("technique")
                    name = item.get("technique_name") or item.get("name")
                    tactics = item.get("tactics") or item.get("tactic") or []
                    if not isinstance(tactics, list):
                        tactics = [tactics]
                    tid = _extract_technique_id(tid or name)
                    if not tid:
                        continue
                    score = item.get("confidence_score") or item.get("confidence") or 0
                    try:
                        score = int(score)
                    except Exception:
                        score = 0
                    normalized.append(
                        {
                            "technique_id": tid,
                            "technique_name": str(name or "").strip(),
                            "tactics": [str(t).strip() for t in tactics if str(t).strip()],
                            "confidence_score": int(max(0, min(100, score))),
                            "reasoning": item.get("reasoning") or "",
                            "matched_signals": item.get("matched_signals") or []
                        }
                    )
                elif isinstance(item, str):
                    tid = _extract_technique_id(item)
                    if not tid:
                        continue
                    normalized.append(
                        {
                            "technique_id": tid,
                            "technique_name": "",
                            "tactics": [],
                            "confidence_score": 0,
                            "reasoning": "",
                            "matched_signals": []
                        }
                    )
            return normalized

        def _add_iocs(key: str, values: Any) -> None:
            if not values:
                return
            if not isinstance(values, list):
                values = [values]
            for value in values:
                value = str(value).strip()
                if value and value not in extracted[key]:
                    extracted[key].append(value)

        key_events = context.get("key_events") or []
        for event in key_events:
            ioc_matches = event.get("ioc_matches") or []
            if isinstance(ioc_matches, list) and ioc_matches:
                mapped_ioc_intel.append({"ioc_matches": ioc_matches})
            for match in ioc_matches:
                if not isinstance(match, dict):
                    continue
                value = str(match.get("ioc") or match.get("value") or "").strip()
                if not value:
                    continue
                ioc_type = str(match.get("type") or "").strip().lower()
                if not ioc_type:
                    ioc_type = self._infer_ioc_type(value)
                if ioc_type == "ip":
                    _add_iocs("ips", value)
                elif ioc_type == "domain":
                    _add_iocs("domains", value)
                elif ioc_type == "sha256":
                    _add_iocs("sha256", value)
                elif ioc_type == "md5":
                    _add_iocs("md5", value)
                elif ioc_type == "cve":
                    _add_iocs("cves", value)
            event_tags = event.get("tags") or (event.get("fields") or {}).get("tags")
            mitre_matches.extend(_normalize_mitre_items(event.get("mitre_matches") or [], event_tags))

        ioc_summary = context.get("ioc_summary") or {}
        for item in ioc_summary.get("high_confidence_iocs") or []:
            if isinstance(item, dict):
                mapped_ioc_intel.append({"ioc_matches": [item]})
                value = str(item.get("ioc") or "").strip()
                if value:
                    inferred = self._infer_ioc_type(value)
                    if inferred == "ip":
                        _add_iocs("ips", value)
                    elif inferred == "domain":
                        _add_iocs("domains", value)
                    elif inferred == "sha256":
                        _add_iocs("sha256", value)
                    elif inferred == "md5":
                        _add_iocs("md5", value)
                    elif inferred == "cve":
                        _add_iocs("cves", value)

        mitre_summary = context.get("mitre_summary") or []
        mitre_matches.extend(_normalize_mitre_items(mitre_summary))

        alert_ioc_matches = alert.get("ioc_matches") or alert.get("ioc_intel") or []
        if isinstance(alert_ioc_matches, list):
            mapped_ioc_intel.extend([m for m in alert_ioc_matches if isinstance(m, dict)])

        alert_mitre = alert.get("mitre") or []
        mitre_matches.extend(_normalize_mitre_items(alert_mitre))

        dedup_mitre = []
        seen = set()
        for match in mitre_matches:
            tid = str(match.get("technique_id") or match.get("id") or "").strip()
            name = str(match.get("technique_name") or match.get("name") or "").strip()
            key = f"{tid}|{name}"
            if key not in seen and (tid or name):
                seen.add(key)
                dedup_mitre.append(match)

        return {
            "extracted_iocs": extracted,
            "mapped_ioc_intel": mapped_ioc_intel,
            "mitre_matches": dedup_mitre
        }

    def _build_investigation_exclusions(self, alert: Dict[str, Any], context: Dict[str, Any]) -> List[str]:
        alert = alert or {}
        context = context or {}
        excluded = set()
        if alert.get("id") is not None:
            excluded.add(str(alert.get("id")))
        evidence = alert.get("evidence") or {}
        for key in ["alert_id", "event_id"]:
            if evidence.get(key):
                excluded.add(str(evidence.get(key)))
        for key in ["processed_ids", "fingerprints"]:
            for value in evidence.get(key) or []:
                excluded.add(str(value))
        processed_logs = context.get("key_events") or []
        for log in processed_logs:
            if log.get("id") is not None:
                excluded.add(str(log.get("id")))
            if log.get("event_id"):
                excluded.add(str(log.get("event_id")))
            if log.get("fingerprint"):
                excluded.add(str(log.get("fingerprint")))
        return list(excluded)

    def _is_ipv4(self, value: str) -> bool:
        return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value or ""))

    def _is_ipv6(self, value: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F:]{2,39}", value or "")) and ":" in (value or "")

    def _is_domain(self, value: str) -> bool:
        return bool(re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}", value or ""))

    def _is_sha256(self, value: str) -> bool:
        return bool(re.fullmatch(r"[a-fA-F0-9]{64}", value or ""))

    def _is_md5(self, value: str) -> bool:
        return bool(re.fullmatch(r"[a-fA-F0-9]{32}", value or ""))

    def _is_cve(self, value: str) -> bool:
        return bool(re.fullmatch(r"CVE-\d{4}-\d{4,7}", value or "", re.IGNORECASE))

    def _is_process_or_file(self, value: str) -> bool:
        return str(value or "").lower().endswith((".exe", ".dll", ".sys", ".bat", ".ps1"))

    def _infer_ioc_type(self, value: str) -> str:
        if self._is_process_or_file(value):
            return "process"
        if self._is_ipv4(value) or self._is_ipv6(value):
            return "ip"
        if self._is_sha256(value):
            return "sha256"
        if self._is_md5(value):
            return "md5"
        if self._is_cve(value):
            return "cve"
        if self._is_domain(value):
            return "domain"
        return "unknown"

    def _clean_ioc_verdicts(
        self,
        ioc_items: List[Dict[str, Any]],
        extracted_iocs: Dict[str, List[str]],
        excluded_values: List[str]
    ) -> List[Dict[str, Any]]:
        excluded = {str(v).strip() for v in excluded_values if str(v).strip()}
        allowed = set()
        for key in ["ips", "domains", "sha256", "md5", "cves"]:
            for value in extracted_iocs.get(key) or []:
                allowed.add(str(value).strip())
        cleaned = []
        for item in ioc_items:
            ioc = str(item.get("ioc") or "").strip()
            if not ioc:
                continue
            if ioc in excluded:
                continue
            if re.fullmatch(r"[0-9a-fA-F-]{36}", ioc):
                continue
            inferred = self._infer_ioc_type(ioc)
            if inferred == "unknown" and ioc not in allowed and not self._is_process_or_file(ioc):
                continue
            ioc_type = str(item.get("type") or "").strip().lower()
            if ioc_type in {"event_id", "alert_id", "processed_id", "fingerprint"}:
                continue
            if inferred in {"ip", "domain", "sha256", "md5", "cve", "process"}:
                ioc_type = inferred
            verdict = str(item.get("verdict") or "unknown").strip().lower()
            if verdict not in {"malicious", "suspicious", "benign", "unknown"}:
                verdict = "unknown"
            confidence = item.get("confidence")
            try:
                confidence = int(confidence)
            except Exception:
                confidence = 0
            confidence = int(max(0, min(100, confidence)))
            evidence = str(item.get("evidence") or item.get("reason") or "").strip()
            cleaned.append(
                {
                    "ioc": ioc,
                    "type": ioc_type or "unknown",
                    "verdict": verdict,
                    "confidence": confidence,
                    "evidence": evidence
                }
            )
        return cleaned

    def _build_investigation_explainability(
        self,
        alert: Dict[str, Any],
        context: Dict[str, Any],
        mitre_items: List[Dict[str, Any]],
        ioc_items: List[Dict[str, Any]]
    ) -> List[str]:
        reasons: List[str] = []
        alert = alert or {}
        severity = str(alert.get("severity") or "").lower()
        if severity:
            reasons.append(f"Alert severity assessed as {severity}")
        if mitre_items:
            for item in mitre_items[:3]:
                tid = str(item.get("technique_id") or "").strip()
                name = str(item.get("name") or "").strip()
                if tid and name:
                    reasons.append(f"Matched MITRE technique {tid} {name}")
                elif tid:
                    reasons.append(f"Matched MITRE technique {tid}")
        for item in ioc_items[:3]:
            verdict = str(item.get("verdict") or "unknown")
            ioc = str(item.get("ioc") or "")
            reasons.append(f"IOC {ioc} classified as {verdict}")
        risk_signals = context.get("risk_signals") or []
        if risk_signals:
            reasons.append("Correlation findings present for related activity")
        if not reasons:
            reasons.append("Limited evidence available beyond alert metadata")
        return reasons[:5]

    def _build_confidence_breakdown(
        self,
        context: Dict[str, Any],
        mitre_items: List[Dict[str, Any]],
        ioc_items: List[Dict[str, Any]],
        alert: Dict[str, Any]
    ) -> Dict[str, int]:
        correlation_findings = context.get("risk_signals") or []
        rule_weight = 20
        severity = str((alert or {}).get("severity") or "").lower()
        if severity in {"high", "critical"}:
            rule_weight = 35
        ioc_weight = 10
        if any(i.get("verdict") in {"malicious", "suspicious"} for i in ioc_items):
            ioc_weight = 30
        mitre_weight = 10
        if mitre_items:
            mitre_weight = 25
        correlation_weight = 5
        if correlation_findings:
            correlation_weight = 20
        ai_weight = 10
        return {
            "mitre_weight": mitre_weight,
            "ioc_weight": ioc_weight,
            "rule_weight": rule_weight,
            "correlation_weight": correlation_weight,
            "ai_weight": ai_weight
        }

    def _build_case_notes(
        self,
        alert: Dict[str, Any],
        context: Dict[str, Any],
        explainability: List[str]
    ) -> str:
        alert = alert or {}
        summary = str(alert.get("summary") or "").strip()
        rule_name = str(alert.get("rule_name") or "").strip()
        created_at = str(alert.get("created_at") or "").strip()
        agent_id = str(alert.get("evidence", {}).get("agent_id") or "").strip()
        hostname = str(alert.get("evidence", {}).get("hostname") or "").strip()
        lines = []
        if created_at:
            lines.append(f"At {created_at}, an alert was generated for {rule_name or 'an observed activity'}.")
        else:
            lines.append(f"An alert was generated for {rule_name or 'an observed activity'}.")
        if summary:
            lines.append(f"Summary: {summary}")
        if agent_id or hostname:
            lines.append(f"Affected asset context: agent {agent_id or 'unknown'} on host {hostname or 'unknown'}.")
        if explainability:
            lines.append("Key observations:")
            for item in explainability:
                lines.append(f"- {item}")
        processed_logs = context.get("key_events") or []
        if processed_logs:
            lines.append("Related processed logs were reviewed for context and supporting evidence.")
        correlation_findings = context.get("risk_signals") or []
        if correlation_findings:
            lines.append("Correlation signals were considered to determine potential multi-stage activity.")
        return "\n".join(lines[:10])

    def _ensure_min_lines(self, text: str, minimum: int, filler: List[str]) -> str:
        text = str(text or "").strip()
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        for item in filler:
            if len(lines) >= minimum:
                break
            if item and item not in lines:
                lines.append(item)
        if not lines:
            lines = filler[:minimum]
        if len(lines) < minimum:
            lines.extend([f"Additional context line {idx + 1}." for idx in range(minimum - len(lines))])
        return "\n".join(lines[: max(minimum, len(lines))])

    def _ensure_min_items(self, items: List[str], minimum: int, filler: List[str]) -> List[str]:
        items = [str(x).strip() for x in items if str(x).strip()]
        for item in filler:
            if len(items) >= minimum:
                break
            if item and item not in items:
                items.append(item)
        if len(items) < minimum:
            items.extend([f"Additional item {idx + 1}" for idx in range(minimum - len(items))])
        return items[: max(minimum, len(items))]

    def _normalize_investigation(
        self,
        parsed: Dict[str, Any],
        alert: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ) -> Dict[str, Any]:
        parsed = parsed or {}
        alert = alert or {}
        context = context or {}

        summary = str(parsed.get("summary") or "").strip()
        if not summary:
            summary = "Insufficient evidence to confirm a definitive incident outcome."

        mitre_mapping = parsed.get("mitre_mapping") or parsed.get("mitre") or []
        if not isinstance(mitre_mapping, list):
            mitre_mapping = [mitre_mapping]
        mitre_items: List[Dict[str, Any]] = []
        for item in mitre_mapping:
            if isinstance(item, dict):
                technique_id = str(item.get("technique_id") or item.get("id") or "").strip()
                name = str(item.get("name") or item.get("technique_name") or "").strip()
                tactics = item.get("tactics") or []
                if not isinstance(tactics, list):
                    tactics = [tactics]
                tactics = [str(t).strip() for t in tactics if str(t).strip()]
                if not technique_id and name:
                    technique_id = name
                if technique_id or name or tactics:
                    mitre_items.append(
                        {
                            "technique_id": technique_id,
                            "name": name,
                            "tactics": tactics
                        }
                    )
            else:
                value = str(item).strip()
                if value:
                    mitre_items.append(
                        {
                            "technique_id": value,
                            "name": value,
                            "tactics": []
                        }
                    )

        ioc_verdicts = parsed.get("ioc_verdicts") or parsed.get("ioc_matches") or []
        if not isinstance(ioc_verdicts, list):
            ioc_verdicts = [ioc_verdicts]
        ioc_items: List[Dict[str, Any]] = []
        for item in ioc_verdicts:
            if not isinstance(item, dict):
                value = str(item).strip()
                if value:
                    ioc_items.append(
                        {
                            "ioc": value,
                            "type": "unknown",
                            "verdict": "unknown",
                            "confidence": 0,
                            "evidence": ""
                        }
                    )
                continue
            ioc = str(item.get("ioc") or item.get("indicator") or "").strip()
            ioc_type = str(item.get("type") or item.get("ioc_type") or "unknown").strip()
            verdict = str(item.get("verdict") or "unknown").strip().lower()
            if verdict not in {"malicious", "suspicious", "benign", "unknown"}:
                verdict = "unknown"
            confidence = item.get("confidence")
            try:
                confidence = int(confidence)
            except Exception:
                confidence = 0
            confidence = int(max(0, min(100, confidence)))
            evidence = str(item.get("evidence") or item.get("reason") or "").strip()
            if ioc:
                ioc_items.append(
                    {
                        "ioc": ioc,
                        "type": ioc_type or "unknown",
                        "verdict": verdict,
                        "confidence": confidence,
                        "evidence": evidence
                    }
                )

        extracted_inputs = self._extract_investigation_inputs(alert, context)
        excluded_values = self._build_investigation_exclusions(alert, context)
        ioc_items = self._clean_ioc_verdicts(
            ioc_items,
            extracted_inputs.get("extracted_iocs") or {},
            excluded_values
        )

        assessment = parsed.get("assessment") or {}
        if not isinstance(assessment, dict):
            assessment = {}
        assessment_is_incident = self._normalize_bool(assessment.get("is_incident"))
        assessment_severity = str(assessment.get("incident_severity") or "").strip().lower()
        assessment_confidence = assessment.get("confidence_score")
        assessment_reasoning = str(assessment.get("reasoning") or "").strip()

        try:
            confidence_score = int(assessment_confidence or parsed.get("confidence_score") or 0)
        except Exception:
            confidence_score = 0
        confidence_score = int(max(0, min(100, confidence_score)))

        is_incident = assessment_is_incident if assessment.get("is_incident") is not None else self._normalize_bool(parsed.get("is_incident"))
        incident_severity = assessment_severity or str(parsed.get("incident_severity") or "").strip().lower()
        if is_incident:
            if incident_severity not in {"low", "medium", "high", "critical"}:
                incident_severity = "medium"
        else:
            incident_severity = "none"
        if not assessment_reasoning:
            assessment_reasoning = "Insufficient evidence to confirm an incident; validate additional telemetry."

        recommended_actions = parsed.get("recommended_actions") or []
        if not isinstance(recommended_actions, list):
            recommended_actions = [recommended_actions]
        recommended_actions = [str(x).strip() for x in recommended_actions if str(x).strip()]
        alert_actions = alert.get("recommended_actions") or []
        if isinstance(alert_actions, list):
            recommended_actions.extend([str(x).strip() for x in alert_actions if str(x).strip()])

        explainability = parsed.get("explainability") or []
        if not isinstance(explainability, list):
            explainability = [explainability]
        explainability = [str(x).strip() for x in explainability if str(x).strip()]
        if not explainability:
            explainability = self._build_investigation_explainability(alert, context, mitre_items, ioc_items)

        case_notes = str(parsed.get("case_notes") or "").strip()
        if not case_notes:
            case_notes = self._build_case_notes(alert, context, explainability)

        confidence_breakdown = parsed.get("confidence_breakdown") or {}
        if not isinstance(confidence_breakdown, dict):
            confidence_breakdown = {}
        if not confidence_breakdown:
            confidence_breakdown = self._build_confidence_breakdown(context, mitre_items, ioc_items, alert)

        summary = self._ensure_min_lines(
            summary,
            3,
            [
                "Alert context reviewed with available evidence and alert metadata.",
                "No external intelligence was used beyond provided context.",
                "Insufficient evidence noted; follow-up validation recommended."
            ]
        )

        case_notes = self._ensure_min_lines(
            case_notes,
            8,
            [
                "Alert evidence was reviewed across available logs and alert metadata.",
                "Suspiciousness is based on rule context and indicator matches provided.",
                "Observed evidence is limited to the supplied alert data.",
                "No corroborating telemetry was provided beyond the evidence bundle.",
                "Missing context includes host activity baselines and authentication history.",
                "Validate process ancestry and user context before escalation.",
                "Confirm network destinations and any matching IOC telemetry.",
                "Continue monitoring for related alerts or correlation findings."
            ]
        )

        explainability = self._ensure_min_items(
            explainability,
            4,
            [
                "Alert classification is based on rule logic and severity context.",
                "IOC or MITRE indicators were evaluated using provided inputs.",
                "Correlation findings were reviewed for related activity.",
                "Evidence gaps were identified; additional validation is required."
            ]
        )

        recommended_actions = self._ensure_min_items(
            recommended_actions,
            3,
            [
                "Collect additional telemetry for the affected host and user.",
                "Validate IOC activity across network and endpoint logs.",
                "Monitor for repeat or correlated activity tied to this alert."
            ]
        )

        timeline = parsed.get("timeline") or []
        timeline_items: List[str] = []
        if isinstance(timeline, list):
            for item in timeline:
                if isinstance(item, str):
                    value = item.strip()
                    if value:
                        timeline_items.append(value)
                    continue
                if isinstance(item, dict):
                    timestamp = str(item.get("timestamp") or item.get("time") or "").strip()
                    event = str(item.get("event") or item.get("activity") or "").strip()
                    source = str(item.get("source") or item.get("log_source") or "").strip()
                    parts = [part for part in [timestamp, event, source] if part]
                    if parts:
                        timeline_items.append(" — ".join(parts))
        timeline_items = self._ensure_min_items(
            timeline_items,
            3,
            [
                "Step 1: Alert triggered and initial evidence collected.",
                "Step 2: Evidence reviewed for IOC and MITRE alignment.",
                "Step 3: Additional validation steps identified."
            ]
        )

        ioc_analysis = parsed.get("ioc_analysis") or {}
        if not isinstance(ioc_analysis, dict):
            ioc_analysis = {}
        observed_iocs = ioc_analysis.get("observed_iocs")
        if not isinstance(observed_iocs, list):
            observed_iocs = [item.get("ioc") for item in ioc_items if item.get("ioc")]
        observed_iocs = [str(x).strip() for x in observed_iocs if str(x).strip()]
        ioc_verdict = str(ioc_analysis.get("ioc_verdict") or "unknown").strip().lower()
        if ioc_verdict not in {"malicious", "suspicious", "unknown", "benign"}:
            ioc_verdict = "unknown"
        ioc_notes = str(ioc_analysis.get("ioc_notes") or "").strip()
        if not ioc_notes:
            ioc_notes = "IOC verdict is based only on provided evidence; validate via additional telemetry."

        mitre_analysis = parsed.get("mitre_analysis") or {}
        if not isinstance(mitre_analysis, dict):
            mitre_analysis = {}
        techniques = mitre_analysis.get("techniques")
        if not isinstance(techniques, list):
            techniques = []
        techniques = [str(x).strip() for x in techniques if str(x).strip()]
        if not techniques:
            techniques = [f"{m.get('technique_id') or m.get('name')}".strip() for m in mitre_items if m.get("technique_id") or m.get("name")]
        tactics = mitre_analysis.get("tactics")
        if not isinstance(tactics, list):
            tactics = []
        tactics = [str(x).strip() for x in tactics if str(x).strip()]
        mitre_notes = str(mitre_analysis.get("mitre_notes") or "").strip()
        if not mitre_notes:
            mitre_notes = "MITRE mapping reflects provided alert context and may require analyst validation."

        assessment = {
            "is_incident": bool(is_incident),
            "incident_severity": incident_severity,
            "confidence_score": confidence_score,
            "reasoning": assessment_reasoning
        }

        return {
            "summary": summary,
            "timeline": timeline_items,
            "mitre_mapping": mitre_items,
            "ioc_verdicts": ioc_items,
            "confidence_score": confidence_score,
            "is_incident": is_incident,
            "incident_severity": incident_severity,
            "recommended_actions": recommended_actions,
            "case_notes": case_notes,
            "explainability": explainability,
            "confidence_breakdown": confidence_breakdown,
            "assessment": assessment,
            "ioc_analysis": {
                "observed_iocs": observed_iocs,
                "ioc_verdict": ioc_verdict,
                "ioc_notes": ioc_notes
            },
            "mitre_analysis": {
                "techniques": techniques,
                "tactics": tactics,
                "mitre_notes": mitre_notes
            },
            "status": "failed" if error_message else "completed",
            "error_message": error_message
        }

    def build_investigation_prompt(self, alert: Dict[str, Any], context: Dict[str, Any]) -> str:
        alert = alert or {}
        context = context or {}
        extracted = self._extract_investigation_inputs(alert, context)
        evidence = alert.get("evidence") or {}
        input_fields = {
            "alert_id": alert.get("id") or alert.get("alert_id"),
            "rule_name": alert.get("rule_name"),
            "rule_id": alert.get("rule_id"),
            "severity": alert.get("severity"),
            "confidence": alert.get("confidence_score"),
            "summary": alert.get("summary"),
            "asset": context.get("asset") or {},
            "key_events": context.get("key_events") or [],
            "ioc_summary": context.get("ioc_summary") or {},
            "mitre_summary": context.get("mitre_summary") or [],
            "risk_signals": context.get("risk_signals") or []
        }
        return f"""
You are a SOC security analysis engine.
Return ONLY valid JSON.
No markdown.
No explanations.
No extra text.
Output must start with {{ and end with }}.

Return fields:
- is_incident (bool)
- confidence_score (0-100 int)
- incident_severity (low|medium|high|critical|none)
- summary (string)
- case_notes (string)

Input Fields:
{json.dumps(input_fields, indent=2)}

Alert:
{json.dumps(alert, indent=2)}

Extracted Inputs:
{json.dumps(extracted, indent=2)}

Structured Context:
{json.dumps(context, indent=2)}
"""

    async def investigate_alert(self, alert: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        prompt = self.build_investigation_prompt(alert, context)
        alert_id = alert.get("id") if isinstance(alert, dict) else None
        self.logger.info(f"AI CALL START model={self.model}", extra={"alert_id": alert_id})
        self.logger.info(f"PROMPT LENGTH={len(prompt)}", extra={"alert_id": alert_id})
        overall_start = time.monotonic()
        normalized, cleaned, raw_response, retry_count, last_retry_reason = await self._investigate_with_retry(prompt, alert, context)
        overall_duration = time.monotonic() - overall_start
        self.logger.info(f"AI CALL DURATION={overall_duration:.2f}s", extra={"alert_id": alert_id})
        return {
            "result": normalized,
            "raw_output": cleaned,
            "raw_response": raw_response,
            "prompt": prompt,
            "model": self.model,
            "retry_count": retry_count,
            "last_retry_reason": last_retry_reason
        }

    async def investigation_smoke_test(self) -> List[Dict[str, Any]]:
        samples = [
            {
                "alert": {
                    "id": 101,
                    "rule_id": "RULE-IOC-001",
                    "rule_name": "Suspicious IOC Match",
                    "severity": "high",
                    "confidence_score": 85,
                    "summary": "Known malicious hash detected in endpoint telemetry.",
                    "evidence": {"processed_ids": [1, 2], "fingerprints": ["fp-001"]},
                    "mitre": [],
                    "ioc_matches": [{"ioc": "8.8.8.8", "verdict": "benign"}],
                    "recommended_actions": ["Block malicious indicators at perimeter"]
                },
                "context": {
                    "processed_logs": [
                        {
                            "id": 1,
                            "timestamp": "2026-01-26T01:00:00Z",
                            "event_type": "dns_query",
                            "message": "Suspicious DNS query observed",
                            "raw": "dns query for example.com",
                            "iocs": {"domains": ["example.com"]},
                            "fields": {}
                        }
                    ],
                    "correlation_findings": []
                }
            },
            {
                "alert": {
                    "id": 102,
                    "rule_id": "RULE-MITRE-002",
                    "rule_name": "MITRE Technique Match",
                    "severity": "medium",
                    "confidence_score": 60,
                    "summary": "Technique match observed in behavior analytics.",
                    "evidence": {"processed_ids": [], "fingerprints": []},
                    "mitre": [{"technique_id": "T1055", "name": "Process Injection"}],
                    "ioc_matches": [],
                    "recommended_actions": []
                },
                "context": {
                    "processed_logs": [],
                    "correlation_findings": [{"title": "Process injection correlation", "severity": "medium"}]
                }
            },
            {
                "alert": {
                    "id": 103,
                    "rule_id": "RULE-MIN-003",
                    "rule_name": "Minimal Evidence Alert",
                    "severity": "low",
                    "confidence_score": 30,
                    "summary": "Minimal evidence alert triggered.",
                    "evidence": {},
                    "mitre": [],
                    "ioc_matches": [],
                    "recommended_actions": []
                },
                "context": {"processed_logs": [], "correlation_findings": []}
            }
        ]
        results = []
        for sample in samples:
            response = await self.investigate_alert(sample["alert"], sample["context"])
            result = response.get("result") or {}
            results.append(result)
            print(json.dumps(result, indent=2))
        return results
