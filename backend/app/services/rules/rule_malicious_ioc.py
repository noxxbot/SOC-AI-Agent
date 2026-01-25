from typing import Any, Dict, List

from app.services.rules.base_rule import BaseRule


class MaliciousIOCRule(BaseRule):
    """
    Emits alerts when IOC intelligence reports malicious verdicts.
    """

    rule_id = "RULE-004"
    rule_name = "Malicious IOC Observed"
    severity = "high"
    category = "threat-intel"

    def evaluate(
        self,
        logs: List[Dict[str, Any]],
        correlation_findings: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        alerts = []
        window_seconds = int(context.get("window_seconds") or 600)
        for event in logs:
            ioc_intel = event.get("ioc_intel") or {}
            summary = ioc_intel.get("ioc_summary") or {}
            matches = ioc_intel.get("ioc_matches") or []
            malicious = summary.get("risk") == "malicious" or any(m.get("verdict") == "malicious" for m in matches)
            if not malicious:
                continue
            confidence = int(summary.get("confidence") or 85)
            evidence = {
                "event_ids": [event.get("event_id")] if event.get("event_id") else [],
                "processed_ids": [event.get("id")] if event.get("id") is not None else [],
                "fingerprints": [event.get("fingerprint")] if event.get("fingerprint") else [],
                "summary": "Malicious IOC detected in processed log"
            }
            alerts.append(
                self._build_alert(
                    confidence_score=confidence,
                    evidence=evidence,
                    recommended_actions=[
                        "Block the IOC in perimeter controls",
                        "Hunt for related activity across endpoints",
                        "Isolate affected host if suspicious activity persists"
                    ],
                    mitre=[],
                    ioc_matches=matches,
                    summary="Malicious IOC detected in processed log",
                    fingerprint_key=event.get("fingerprint") or str(event.get("id") or ""),
                    timestamp=event.get("ts"),
                    window_seconds=window_seconds
                )
            )
        return alerts
