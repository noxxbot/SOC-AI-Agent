from typing import Any, Dict, List

from app.services.rules.base_rule import BaseRule


class PowerShellEncodedRule(BaseRule):
    """
    Detects encoded PowerShell execution in a single event.
    """

    rule_id = "RULE-002"
    rule_name = "PowerShell Encoded Command"
    severity = "high"
    category = "execution"

    def evaluate(
        self,
        logs: List[Dict[str, Any]],
        correlation_findings: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        alerts = []
        window_seconds = int(context.get("window_seconds") or 600)
        for event in logs:
            if not self._is_encoded_powershell(event):
                continue
            summary = "Encoded PowerShell command execution detected"
            evidence = {
                "event_ids": [event.get("event_id")] if event.get("event_id") else [],
                "processed_ids": [event.get("id")] if event.get("id") is not None else [],
                "fingerprints": [event.get("fingerprint")] if event.get("fingerprint") else [],
                "summary": summary
            }
            alerts.append(
                self._build_alert(
                    confidence_score=80,
                    evidence=evidence,
                    recommended_actions=[
                        "Inspect PowerShell command line and script content",
                        "Check parent process and user context",
                        "Hunt for related persistence or lateral movement"
                    ],
                    mitre=[
                        {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactics": ["execution"]},
                        {"technique_id": "T1027", "technique_name": "Obfuscated/Compressed Files", "tactics": ["defense-evasion"]}
                    ],
                    ioc_matches=[],
                    summary=summary,
                    fingerprint_key=event.get("fingerprint") or str(event.get("id") or ""),
                    timestamp=event.get("ts"),
                    window_seconds=window_seconds
                )
            )
        return alerts

    def _is_encoded_powershell(self, event: Dict[str, Any]) -> bool:
        tags = event.get("tags") or []
        raw = str(event.get("raw") or "").lower()
        message = str(event.get("message") or "").lower()
        combined = f"{raw} {message}"
        return (
            "encoded_command" in tags
            or ("powershell" in combined and ("-enc" in combined or "-encodedcommand" in combined))
        )
