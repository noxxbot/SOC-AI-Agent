from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

from app.core.config import settings
from app.database.db import get_db
from app.models.correlation_finding import CorrelationFinding
from app.services.correlation_scheduler import run_correlation_once

router = APIRouter()


def _parse_json(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


@router.get("/correlation/findings/recent", response_model=List[Dict[str, Any]])
def get_recent_findings(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    findings = (
        db.query(CorrelationFinding)
        .order_by(CorrelationFinding.created_at.desc())
        .limit(limit)
        .all()
    )
    results = []
    for f in findings:
        results.append(
            {
                "id": f.id,
                "created_at": f.created_at.isoformat() if f.created_at else None,
                "window_start": f.window_start.isoformat() if f.window_start else None,
                "window_end": f.window_end.isoformat() if f.window_end else None,
                "title": f.title,
                "severity": f.severity,
                "confidence_score": f.confidence_score,
                "entities": _parse_json(f.entities_json, {}),
                "evidence": _parse_json(f.evidence_json, []),
                "mitre_summary": _parse_json(f.mitre_json, []),
                "ioc_summary": _parse_json(f.ioc_json, {}),
                "summary_text": f.summary_text,
                "status": f.status,
                "fingerprint": f.fingerprint
            }
        )
    return results


@router.post("/correlation/run", response_model=Dict[str, Any])
def run_correlation():
    if not settings.DEBUG:
        raise HTTPException(status_code=404, detail="Not found")
    return run_correlation_once()
