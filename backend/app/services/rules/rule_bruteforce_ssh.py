from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.services.rules.base_rule import BaseRule


class BruteForceSSHRule(BaseRule):
    """
    Detects repeated SSH login failures from the same source within a short window.
    """

    rule_id = "RULE-001"
    rule_name = "Brute Force SSH"
    severity = "high"
    category = "authentication"

    def evaluate(
        self,
        logs: List[Dict[str, Any]],
        correlation_findings: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        window_seconds = int(context.get("window_seconds") or 600)
        threshold_window = min(120, window_seconds)
        now = context.get("now") or datetime.now(timezone.utc)

        candidates = []
        for event in logs:
            if not self._is_failed_login(event):
                continue
            if not self._is_ssh(event):
                continue
            candidates.append(event)

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for event in candidates:
            ts = event.get("ts")
            if not ts or ts < now - timedelta(seconds=threshold_window):
                continue
            src_ip = self._extract_source_ip(event)
            user = self._extract_user(event) or "unknown"
            hostname = event.get("hostname") or "unknown"
            if not src_ip:
                continue
            key = f"{src_ip}|{user}|{hostname}"
            grouped.setdefault(key, []).append(event)

        alerts = []
        for key, events in grouped.items():
            if len(events) < 5:
                continue
            src_ip, user, hostname = key.split("|")
            event_ids = [e.get("event_id") for e in events if e.get("event_id")]
            processed_ids = [e.get("id") for e in events if e.get("id") is not None]
            fingerprints = [e.get("fingerprint") for e in events if e.get("fingerprint")]
            summary = f"{len(events)} failed SSH logins from {src_ip} within {threshold_window} seconds"
            evidence = {
                "event_ids": event_ids,
                "processed_ids": processed_ids,
                "fingerprints": fingerprints,
                "summary": summary
            }
            alerts.append(
                self._build_alert(
                    confidence_score=85,
                    evidence=evidence,
                    recommended_actions=[
                        "Block IP at firewall",
                        "Reset affected account credentials",
                        "Enable MFA",
                        "Review auth logs for lateral movement"
                    ],
                    mitre=[{"technique_id": "T1110", "technique_name": "Brute Force", "tactics": ["credential-access"]}],
                    ioc_matches=[{"ioc": src_ip, "type": "ip", "verdict": "suspicious", "source": "rule_engine"}],
                    summary=summary,
                    fingerprint_key=key,
                    timestamp=events[0].get("ts") or now,
                    window_seconds=window_seconds
                )
            )
        return alerts

    def _extract_source_ip(self, event: Dict[str, Any]) -> Optional[str]:
        fields = event.get("fields") or {}
        return fields.get("source_ip") or fields.get("src_ip") or fields.get("remote_ip")

    def _extract_user(self, event: Dict[str, Any]) -> Optional[str]:
        fields = event.get("fields") or {}
        return fields.get("user") or fields.get("username")

    def _is_failed_login(self, event: Dict[str, Any]) -> bool:
        event_type = str(event.get("event_type") or "").lower()
        category = str(event.get("category") or "").lower()
        message = str(event.get("message") or "").lower()
        return (
            event_type in {"failed_login", "login_failed"}
            or (category == "auth" and "failed" in event_type)
            or "failed password" in message
        )

    def _is_ssh(self, event: Dict[str, Any]) -> bool:
        fields = event.get("fields") or {}
        proto = str(fields.get("protocol") or "").lower()
        message = str(event.get("message") or "").lower()
        raw = str(event.get("raw") or "").lower()
        return proto == "ssh" or "ssh" in message or "ssh" in raw
