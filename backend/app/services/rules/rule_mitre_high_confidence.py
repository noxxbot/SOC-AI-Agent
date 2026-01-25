from typing import Any, Dict, List

from app.services.rules.base_rule import BaseRule


class MitreHighConfidenceRule(BaseRule):
    """
    Triggers alerts for high-confidence MITRE technique matches.
    """

    rule_id = "RULE-005"
    rule_name = "High Confidence MITRE Technique"
    severity = "medium"
    category = "behavior"

    def evaluate(
        self,
        logs: List[Dict[str, Any]],
        correlation_findings: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        alerts = []
        window_seconds = int(context.get("window_seconds") or 600)
        for event in logs:
            matches = event.get("mitre_matches") or []
            for match in matches:
                tid = match.get("technique_id")
                score = int(match.get("confidence_score") or 0)
                if tid == "T1059.001" and score >= 70:
                    alerts.append(self._emit(event, match, score, window_seconds))
                if tid == "T1027" and score >= 60:
                    alerts.append(self._emit(event, match, score, window_seconds))
        return alerts

    def _emit(
        self,
        event: Dict[str, Any],
        match: Dict[str, Any],
        score: int,
        window_seconds: int
    ) -> Dict[str, Any]:
        tid = match.get("technique_id")
        tname = match.get("technique_name")
        summary = f"High confidence MITRE match: {tid} {tname}".strip()
        evidence = {
            "event_ids": [event.get("event_id")] if event.get("event_id") else [],
            "processed_ids": [event.get("id")] if event.get("id") is not None else [],
            "fingerprints": [event.get("fingerprint")] if event.get("fingerprint") else [],
            "summary": summary
        }
        return self._build_alert(
            confidence_score=score,
            evidence=evidence,
            recommended_actions=[
                "Review the activity for associated tactics",
                "Validate if the behavior is expected for the host",
                "Investigate related events within the same time window"
            ],
            mitre=[{
                "technique_id": tid,
                "technique_name": tname,
                "tactics": match.get("tactics") or []
            }],
            ioc_matches=[],
            summary=summary,
            fingerprint_key=f"{tid}|{event.get('fingerprint') or event.get('id')}",
            timestamp=event.get("ts"),
            window_seconds=window_seconds
        )
