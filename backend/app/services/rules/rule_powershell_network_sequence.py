from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from app.services.rules.base_rule import BaseRule


class PowerShellNetworkSequenceRule(BaseRule):
    """
    Detects PowerShell encoded execution followed by network activity.
    """

    rule_id = "RULE-007"
    rule_name = "PowerShell Encoded Followed By Network"
    severity = "high"
    category = "sequence"

    def evaluate(
        self,
        logs: List[Dict[str, Any]],
        correlation_findings: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        window_seconds = int(context.get("window_seconds") or 600)
        now = context.get("now") or datetime.now(timezone.utc)
        threshold_window = min(180, window_seconds)

        powershell_events = []
        network_events = []
        for event in logs:
            if self._is_encoded_powershell(event):
                powershell_events.append(event)
            if self._is_network_event(event):
                network_events.append(event)

        alerts = []
        for ps_event in powershell_events:
            ts = ps_event.get("ts")
            if not ts or ts < now - timedelta(seconds=threshold_window):
                continue
            hostname = ps_event.get("hostname")
            related = [
                e for e in network_events
                if e.get("hostname") == hostname
                and e.get("ts")
                and e.get("ts") >= ts
                and e.get("ts") <= ts + timedelta(seconds=threshold_window)
            ]
            if not related:
                continue
            event_ids = []
            processed_ids = []
            fingerprints = []
            for e in [ps_event] + related[:3]:
                if e.get("event_id"):
                    event_ids.append(e.get("event_id"))
                if e.get("id") is not None:
                    processed_ids.append(e.get("id"))
                if e.get("fingerprint"):
                    fingerprints.append(e.get("fingerprint"))
            summary = "PowerShell encoded command followed by network activity"
            evidence = {
                "event_ids": event_ids,
                "processed_ids": processed_ids,
                "fingerprints": fingerprints,
                "summary": summary
            }
            alerts.append(
                self._build_alert(
                    confidence_score=82,
                    evidence=evidence,
                    recommended_actions=[
                        "Inspect PowerShell command and network destinations",
                        "Check for downloaded payloads or scripts",
                        "Isolate host if suspicious activity persists"
                    ],
                    mitre=[{"technique_id": "T1059.001", "technique_name": "PowerShell", "tactics": ["execution"]}],
                    ioc_matches=[],
                    summary=summary,
                    fingerprint_key=f"{hostname}|{ps_event.get('fingerprint') or ps_event.get('id')}",
                    timestamp=ps_event.get("ts"),
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

    def _is_network_event(self, event: Dict[str, Any]) -> bool:
        event_type = str(event.get("event_type") or "").lower()
        category = str(event.get("category") or "").lower()
        return category == "network" or event_type in {"dns_query", "http_request", "net_conn", "network_connection"}
