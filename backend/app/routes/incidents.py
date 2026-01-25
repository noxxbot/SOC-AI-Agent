from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Any, Dict, List, Optional
import json

from app.database.db import get_db
from app.models.detection_alert import DetectionAlert
from app.models.incident import Incident
from app.services.incident_engine import build_incident_context, decide_incident, create_or_link_incident

router = APIRouter()


class IncidentRecord(BaseModel):
    id: int
    created_at: Optional[str]
    updated_at: Optional[str]
    title: str
    summary: Optional[str]
    severity: str
    confidence_score: int
    incident_fingerprint: str
    source: str
    agent_id: Optional[str]
    hostname: Optional[str]
    primary_iocs: List[Dict[str, Any]]
    mitre_techniques: List[Dict[str, Any]]
    related_alert_ids: List[int]
    related_log_fingerprints: List[str]
    decision_reason: Optional[str]


def _parse_json(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _map_incident(row: Incident) -> Dict[str, Any]:
    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "title": row.title,
        "summary": row.summary,
        "severity": row.severity,
        "confidence_score": row.confidence_score,
        "incident_fingerprint": row.incident_fingerprint,
        "source": row.source,
        "agent_id": row.agent_id,
        "hostname": row.hostname,
        "primary_iocs": _parse_json(row.primary_iocs_json, []),
        "mitre_techniques": _parse_json(row.mitre_techniques_json, []),
        "related_alert_ids": _parse_json(row.related_alert_ids_json, []),
        "related_log_fingerprints": _parse_json(row.related_log_fingerprints_json, []),
        "decision_reason": row.decision_reason
    }


@router.post("/incidents/auto-create/{alert_id}", response_model=Dict[str, Any])
async def auto_create_incident(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(DetectionAlert).filter(DetectionAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Detection alert not found")

    context = build_incident_context(db, alert)
    decision = decide_incident(alert, context)
    incident = create_or_link_incident(db, decision, alert)
    return {
        "decision": decision,
        "incident": _map_incident(incident) if incident else None
    }


@router.get("/incidents/recent", response_model=List[IncidentRecord])
def recent_incidents(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    rows = (
        db.query(Incident)
        .order_by(Incident.created_at.desc())
        .limit(limit)
        .all()
    )
    return [_map_incident(r) for r in rows]
