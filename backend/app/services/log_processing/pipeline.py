import os
from typing import Any, Dict, List

from app.schemas.log_processing import EnrichedLog
from app.services.log_processing.enrichment_engine import enrich_log
from app.services.log_processing.normalization_engine import normalize_log


def _debug_enabled() -> bool:
    value = os.getenv("LOG_PROCESSING_DEBUG", "")
    return value.lower() in {"1", "true", "yes"}


def process_logs_batch(agent_id: str, hostname: str, timestamp: Any, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    processed: List[Dict[str, Any]] = []
    skipped_invalid = 0
    for log in logs or []:
        try:
            normalized = normalize_log(log, agent_id, hostname, timestamp)
            enriched = enrich_log(normalized)
            combined = {**normalized, **enriched}
            validated = EnrichedLog(**combined).dict()
            processed.append(validated)
        except Exception:
            skipped_invalid += 1
    if _debug_enabled():
        print(f"log_processing processed={len(processed)} received={len(logs or [])} skipped_invalid={skipped_invalid}")
    return {"processed": processed, "skipped_invalid": skipped_invalid}
