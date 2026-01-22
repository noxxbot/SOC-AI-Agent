import os
import json
import re
import httpx
from typing import Dict, Any, List, Optional


class AIService:
    def __init__(self):
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "llama3:8b")

    async def _ask_ollama(self, prompt: str) -> str:
        url = f"{self.ollama_url}/api/generate"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }

        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")

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

    def _extract_json_from_text(self, text: str) -> str:
        """
        Sometimes model returns extra text before/after JSON.
        This tries to extract the first valid JSON object block.
        """
        if not text:
            return ""

        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start:end + 1]

        return text

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

    def _safe_default_analysis(self, explanation: str) -> Dict[str, Any]:
        """
        Safe fallback if JSON parsing fails.
        Always returns schema expected by FastAPI response model.
        """
        return {
            "riskScore": 60,
            "threatDetected": True,
            "explanation": explanation,
            "recommendations": [
                "Review authentication logs for abnormal patterns",
                "Block suspicious IP temporarily (if confirmed malicious)",
                "Enable MFA for privileged accounts",
                "Reset passwords for impacted users"
            ],
            "threatVectors": {
                "persistence": False,
                "lateralMovement": False,
                "exfiltration": False,
                "reconnaissance": True,
                "credentialAccess": True
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

        # If nothing exists anywhere -> return a strict negative summary WITHOUT LLM
        if corr_count == 0 and nvd_count == 0 and kev_count == 0 and otx_count == 0:
            return (
                "⚠️ No reliable correlation found.\n\n"
                f"Query: {query}\n"
                "Result: No matching alerts in SOC DB + no external intel matches.\n\n"
                "Next steps:\n"
                "- Verify the query (try a real CVE like CVE-2021-44228)\n"
                "- Try searching with an IP/domain/hash from your alert logs\n"
                "- Ensure your agents are generating alerts for this activity"
            ).strip()

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
- If external intel is empty, say "No public intel found".
- Do NOT invent CVSS, exploited status, vendor/product, or attack details.
- If query looks invalid/fake, warn the analyst clearly.
- Output must be short, SOC-ready, and actionable.
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

Write in this format:

1) What we searched
2) What we found internally
3) What external intel confirms
4) Recommended next steps (3 bullets)
"""

        out = await self._ask_ollama(prompt)
        return out.strip()

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

        raw = await self._ask_ollama(prompt)
        cleaned = self._clean_llm_output(raw)
        extracted = self._extract_json_from_text(cleaned)

        try:
            parsed = json.loads(extracted)
            qtype = str(parsed.get("type", "")).strip()
            reason = str(parsed.get("reason", "")).strip()

            allowed = {"ioc_query", "mitre_query", "analyst_question", "out_of_scope", "unsafe_request"}
            if qtype not in allowed:
                return {"type": "out_of_scope", "reason": "Classifier returned invalid type"}

            return {"type": qtype, "reason": reason or "Classified successfully"}
        except Exception:
            # fallback conservative
            return {"type": "analyst_question", "reason": "Classifier JSON failed; fallback to analyst_question"}

    # =========================================================
    # Phase 5 Step 3: Cybersecurity Guardrail (NEW)
    # - Block offensive/hacking instructions
    # - Allow only defensive/SOC guidance
    # =========================================================
    def _is_disallowed_request(self, query: str) -> bool:
        """
        Blocks malicious / offensive / hacking requests.
        Conservative guardrail.
        """
        if not query:
            return False

        q = query.strip().lower()

        disallowed_keywords = [
            # hacking / intrusion
            "hack", "bypass", "exploit", "payload", "reverse shell", "shellcode",
            "metasploit", "msfvenom", "cobalt strike", "beacon",
            "sql injection", "xss payload", "csrf bypass", "rce",
            "privilege escalation exploit", "0day", "zero day",
            "crack password", "bruteforce", "brute force attack",
            "steal", "phish", "phishing kit", "credential dump",
            "mimikatz", "dump lsass", "keylogger",

            # malware creation
            "create malware", "make malware", "write malware", "build malware",

            # illegal intent
            "how to break into", "how to attack", "ddos", "botnet"
        ]

        return any(k in q for k in disallowed_keywords)

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

    def is_cybersecurity_related_query(self, query: str) -> bool:
        """
        Lightweight fallback check.
        Not used for main classification (AI does it),
        but useful as safety fallback.
        """
        if not query:
            return False

        q = query.strip().lower()

        cyber_signals = [
            "cve-", "ioc", "mitre", "tactic", "technique", "apt",
            "siem", "soc", "edr", "xdr", "ids", "ips",
            "incident response", "forensics", "malware", "ransomware", "phishing",
            "windows event", "sysmon", "splunk", "sigma", "yara",
            "hash", "sha256", "md5", "domain", "ip address"
        ]

        return any(s in q for s in cyber_signals)

    def safe_refuse_and_redirect(self, query: str) -> str:
        """
        If user asks out-of-topic questions, redirect them back to cybersecurity.
        """
        return (
            "⚠️ I can only help with Cybersecurity / SOC / Threat Intel topics in this system.\n\n"
            f"Your query: {query}\n\n"
            "Try asking something like:\n"
            "- What is process injection and how to detect it?\n"
            "- Explain lateral movement with examples\n"
            "- Search CVE-2021-44228\n"
            "- What does T1055 mean in MITRE ATT&CK?\n"
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

        # ✅ Guardrail first
        if self._is_disallowed_request(query):
            return self._guardrail_refusal(query)

        # still block non-cyber questions
        if not self.is_cybersecurity_related_query(query):
            return self.safe_refuse_and_redirect(query)

        prompt = f"""
You are a Senior SOC Analyst and Cybersecurity Expert.

User Question:
{query}

STRICT RULES:
- Answer only in cybersecurity / blue-team / defensive context.
- DO NOT provide hacking steps, exploitation instructions, payloads, malware creation, or bypass methods.
- If user asks offensive steps, refuse and provide defensive alternatives only.
- If the question is small, give a small simple answer.
- If the question is complex, give a detailed but easy answer.
- Do NOT hallucinate or make up facts.
- If not enough info, say: "Not enough data" and suggest what logs/telemetry to check.
- Keep answer under {max_words} words.

Helpful Context (may be empty):
{json.dumps(context, indent=2)}

Answer format:
- Short Answer
- Detection Ideas (2-4 bullets)
- Mitigation / Response (2-4 bullets)
"""

        out = await self._ask_ollama(prompt)
        return out.strip()

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
        cleaned = self._clean_llm_output(raw_output)
        extracted = self._extract_json_from_text(cleaned)

        try:
            parsed = json.loads(extracted)

            risk_score = parsed.get("riskScore", 50)
            threat_detected = parsed.get("threatDetected", True)
            explanation = parsed.get("explanation", "Suspicious activity detected based on log patterns.")
            explanation = self._fix_explanation_if_json(explanation)
            recommendations = parsed.get("recommendations", ["Review logs", "Investigate source"])
            threat_vectors = parsed.get("threatVectors", {})

            # Fix types
            try:
                risk_score = int(risk_score)
            except Exception:
                risk_score = 50

            risk_score = int(max(0, min(100, risk_score)))
            threat_detected = self._normalize_bool(threat_detected)

            # Ensure recommendations is always list[str]
            if not isinstance(recommendations, list):
                recommendations = [str(recommendations)]

            recommendations = [str(x) for x in recommendations if str(x).strip()]

            # Normalize threatVectors to correct dict booleans
            threat_vectors = self._normalize_threat_vectors(threat_vectors)

            return {
                "riskScore": risk_score,
                "threatDetected": threat_detected,
                "explanation": explanation,
                "recommendations": recommendations,
                "threatVectors": threat_vectors
            }

        except Exception:
            return self._safe_default_analysis(raw_output)

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
        cleaned = self._clean_llm_output(raw_output)
        extracted = self._extract_json_from_text(cleaned)

        try:
            parsed = json.loads(extracted)

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

        except Exception:
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
