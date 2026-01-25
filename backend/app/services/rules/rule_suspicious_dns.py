import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.services.rules.base_rule import BaseRule


class SuspiciousDNSRule(BaseRule):
    """
    Detects high-frequency DNS queries to suspicious-looking domains.
    """

    rule_id = "RULE-003"
    rule_name = "Suspicious DNS Burst"
    severity = "medium"
    category = "network"

    def evaluate(
        self,
        logs: List[Dict[str, Any]],
        correlation_findings: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        window_seconds = int(context.get("window_seconds") or 600)
        threshold_window = min(60, window_seconds)
        now = context.get("now") or datetime.now(timezone.utc)
        group_by = context.get("group_by") or "hostname"

        candidates = []
        for event in logs:
            if not self._is_dns_event(event):
                continue
            domain = self._extract_domain(event)
            if not domain or not self._is_suspicious_domain(domain):
                continue
            candidates.append({**event, "domain": domain})

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for event in candidates:
            ts = event.get("ts")
            if not ts or ts < now - timedelta(seconds=threshold_window):
                continue
            group_key = self._group_key(event, group_by)
            if not group_key:
                continue
            grouped.setdefault(group_key, []).append(event)

        alerts = []
        for key, events in grouped.items():
            if len(events) < 10:
                continue
            event_ids = [e.get("event_id") for e in events if e.get("event_id")]
            processed_ids = [e.get("id") for e in events if e.get("id") is not None]
            fingerprints = [e.get("fingerprint") for e in events if e.get("fingerprint")]
            domains = sorted({e.get("domain") for e in events if e.get("domain")})
            summary = f"{len(events)} suspicious DNS queries within {threshold_window} seconds"
            evidence = {
                "event_ids": event_ids,
                "processed_ids": processed_ids,
                "fingerprints": fingerprints,
                "domains": domains,
                "summary": summary
            }
            alerts.append(
                self._build_alert(
                    confidence_score=70,
                    evidence=evidence,
                    recommended_actions=[
                        "Inspect queried domains for potential C2 activity",
                        "Block suspicious domains at DNS or proxy layer",
                        "Review host processes responsible for DNS activity"
                    ],
                    mitre=[{"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactics": ["command-and-control"]}],
                    ioc_matches=[{"ioc": d, "type": "domain", "verdict": "suspicious", "source": "rule_engine"} for d in domains[:3]],
                    summary=summary,
                    fingerprint_key=f"{key}|{len(events)}",
                    timestamp=events[0].get("ts"),
                    window_seconds=window_seconds
                )
            )
        return alerts

    def _group_key(self, event: Dict[str, Any], group_by: str) -> Optional[str]:
        if group_by == "agent_id":
            return event.get("agent_id")
        if group_by == "source_ip":
            fields = event.get("fields") or {}
            return fields.get("source_ip") or fields.get("src_ip") or fields.get("remote_ip")
        return event.get("hostname")

    def _is_dns_event(self, event: Dict[str, Any]) -> bool:
        event_type = str(event.get("event_type") or "").lower()
        category = str(event.get("category") or "").lower()
        return category in {"network", "dns"} and (event_type in {"dns_query", "dns"} or "dns" in event_type)

    def _extract_domain(self, event: Dict[str, Any]) -> Optional[str]:
        fields = event.get("fields") or {}
        return fields.get("query") or fields.get("domain")

    def _is_suspicious_domain(self, domain: str) -> bool:
        if len(domain) >= 30:
            return True
        if domain.count(".") >= 4:
            return True
        if re.search(r"\d{3,}", domain):
            return True
        label = domain.split(".")[0]
        return len(label) >= 20
