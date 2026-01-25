import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class BaseRule:
    """
    Base rule with helper utilities to emit normalized alert objects.
    """

    rule_id: str = "RULE-BASE"
    rule_name: str = "Base Rule"
    severity: str = "low"
    category: str = "general"

    def evaluate(
        self,
        logs: List[Dict[str, Any]],
        correlation_findings: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError()

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _bucket_time(self, ts: datetime, window_seconds: int) -> str:
        bucket_seconds = max(1, window_seconds)
        epoch = int(ts.timestamp())
        bucket = epoch - (epoch % bucket_seconds)
        return datetime.fromtimestamp(bucket, tz=timezone.utc).isoformat()

    def _fingerprint(self, key: str, ts: Optional[datetime], window_seconds: int) -> str:
        base_ts = ts or datetime.now(timezone.utc)
        bucket = self._bucket_time(base_ts, window_seconds)
        payload = f"{self.rule_id}|{key}|{bucket}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _build_alert(
        self,
        confidence_score: int,
        evidence: Dict[str, Any],
        recommended_actions: List[str],
        mitre: Optional[List[Dict[str, Any]]] = None,
        ioc_matches: Optional[List[Dict[str, Any]]] = None,
        summary: Optional[str] = None,
        fingerprint_key: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        window_seconds: int = 600
    ) -> Dict[str, Any]:
        alert_id = str(uuid.uuid4())
        fingerprint = self._fingerprint(fingerprint_key or alert_id, timestamp, window_seconds)
        # Evidence carries a stable alert_id for traceability across layers.
        return {
            "alert_id": alert_id,
            "created_at": self._now_iso(),
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "confidence_score": int(confidence_score),
            "category": self.category,
            "mitre": mitre or [],
            "ioc_matches": ioc_matches or [],
            "evidence": {
                **evidence,
                "alert_id": alert_id,
                "summary": summary or evidence.get("summary", "")
            },
            "recommended_actions": recommended_actions,
            "status": "open",
            "fingerprint": fingerprint,
            "summary": summary or evidence.get("summary", "")
        }
