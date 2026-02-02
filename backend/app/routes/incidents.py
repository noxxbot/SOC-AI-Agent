from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Any, Dict, List, Optional
import json

from app.core.config import settings
from app.database.db import get_db
from app.models.ai_investigation import AIInvestigation
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
    confidence_breakdown: Dict[str, Any]
    confidence_explanation: Optional[str]
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


def _confidence_from_alerts(db: Session, row: Incident) -> Dict[str, Any]:
    related_alert_ids = _parse_json(row.related_alert_ids_json, [])
    if not related_alert_ids:
        return {"confidence_breakdown": {}, "confidence_explanation": ""}
    alert = (
        db.query(DetectionAlert)
        .filter(DetectionAlert.id.in_(related_alert_ids))
        .order_by(DetectionAlert.created_at.desc())
        .first()
    )
    if not alert:
        return {"confidence_breakdown": {}, "confidence_explanation": ""}
    evidence = _parse_json(alert.evidence_json, {})
    return {
        "confidence_breakdown": evidence.get("confidence_breakdown") or {},
        "confidence_explanation": evidence.get("confidence_explanation") or ""
    }


def _map_incident(row: Incident, db: Session) -> Dict[str, Any]:
    confidence = _confidence_from_alerts(db, row)
    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "title": row.title,
        "summary": row.summary,
        "severity": row.severity,
        "confidence_score": row.confidence_score,
        "confidence_breakdown": confidence.get("confidence_breakdown") or {},
        "confidence_explanation": confidence.get("confidence_explanation") or "",
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

    ai_row = (
        db.query(AIInvestigation)
        .filter(AIInvestigation.alert_id == alert.id)
        .order_by(AIInvestigation.created_at.desc())
        .first()
    )
    threshold = int(getattr(settings, "INCIDENT_AI_MIN_CONFIDENCE", 60) or 60)
    if (
        not ai_row
        or ai_row.status != "completed"
        or not ai_row.is_incident
        or int(ai_row.confidence_score or 0) < threshold
    ):
        raise HTTPException(status_code=409, detail="AI investigation not confirmed for incident creation")

    context = build_incident_context(db, alert)
    decision = decide_incident(alert, context)
    decision["should_create"] = True
    decision["confidence_score"] = max(int(decision.get("confidence_score") or 0), int(ai_row.confidence_score or 0))
    decision["source"] = "ai_investigation"
    decision["reason"] = "AI investigation confirmed incident"
    decision["summary"] = alert.summary or decision.get("summary") or "AI investigation confirmed incident"
    decision["severity"] = ai_row.incident_severity or decision.get("severity") or "low"
    incident = create_or_link_incident(db, decision, alert)
    return {
        "decision": decision,
        "incident": _map_incident(incident, db) if incident else None
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
    return [_map_incident(r, db) for r in rows]


@router.get("/incidents/{incident_id}", response_model=IncidentRecord)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    row = db.query(Incident).filter(Incident.id == incident_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _map_incident(row, db)
