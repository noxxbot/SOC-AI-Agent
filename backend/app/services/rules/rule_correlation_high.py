from typing import Any, Dict, List

from app.services.rules.base_rule import BaseRule


class CorrelationHighSeverityRule(BaseRule):
    """
    Promotes high severity correlation findings into detection alerts.
    """

    rule_id = "RULE-006"
    rule_name = "High Severity Correlation Finding"
    severity = "high"
    category = "correlation"

    def evaluate(
        self,
        logs: List[Dict[str, Any]],
        correlation_findings: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        alerts = []
        window_seconds = int(context.get("window_seconds") or 600)
        for finding in correlation_findings:
            if str(finding.get("severity") or "").lower() != "high":
                continue
            summary = f"Correlation finding: {finding.get('title')}"
            evidence = {
                "event_ids": [e.get("event_id") for e in finding.get("evidence", []) if e.get("event_id")],
                "fingerprints": [e.get("fingerprint") for e in finding.get("evidence", []) if e.get("fingerprint")],
                "summary": summary
            }
            alerts.append(
                self._build_alert(
                    confidence_score=int(finding.get("confidence_score") or 80),
                    evidence=evidence,
                    recommended_actions=[
                        "Review correlated events for root cause",
                        "Validate alert coverage for the observed pattern",
                        "Escalate if additional indicators are present"
                    ],
                    mitre=finding.get("mitre_summary") or [],
                    ioc_matches=finding.get("ioc_summary", {}).get("ioc_matches") if isinstance(finding.get("ioc_summary"), dict) else [],
                    summary=summary,
                    fingerprint_key=finding.get("fingerprint") or str(finding.get("id") or ""),
                    timestamp=finding.get("ts"),
                    window_seconds=window_seconds
                )
            )
        return alerts
