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
from app.services.ai_service import AIService

router = APIRouter()
ai_service = AIService()


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

class TacticalBriefingResponse(BaseModel):
    focus: str
    actions: List[str]
    data_gaps: List[str]



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


@router.post("/incidents/{incident_id}/tactical-briefing", response_model=TacticalBriefingResponse)
async def get_tactical_briefing(incident_id: int, db: Session = Depends(get_db)):
    row = db.query(Incident).filter(Incident.id == incident_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    related_alert_ids = _parse_json(row.related_alert_ids_json, [])
    alerts = []
    if related_alert_ids:
        alerts = (
            db.query(DetectionAlert)
            .filter(DetectionAlert.id.in_(related_alert_ids))
            .all()
        )

    # Pull latest completed AI investigation for context (if any)
    investigation_payload = {}
    ai_confidence = 0
    if related_alert_ids:
        investigations = (
            db.query(AIInvestigation)
            .filter(AIInvestigation.alert_id.in_(related_alert_ids))
            .order_by(AIInvestigation.created_at.desc())
            .all()
        )
        completed = [i for i in investigations if str(i.status or '').lower() == 'completed']
        chosen = completed[0] if completed else (investigations[0] if investigations else None)
        if chosen:
            investigation_payload = _parse_json(chosen.investigation_json, {}) or {}
            ai_confidence = int(chosen.confidence_score or 0)

    # Aggregate structured context
    mitre_entries = []
    ioc_entries = []
    correlation_findings = []
    rule_names = []

    for alert in alerts:
        rule_names.append(alert.rule_name)
        mitre_entries += _parse_json(alert.mitre_json, []) or []
        ioc_entries += _parse_json(alert.ioc_json, []) or []
        evidence = _parse_json(alert.evidence_json, {}) or {}
        reasons = evidence.get('correlation_reasons') or []
        if isinstance(reasons, list):
            correlation_findings += reasons

    mitre_entries += _parse_json(row.mitre_techniques_json, []) or []
    ioc_entries += _parse_json(row.primary_iocs_json, []) or []

    def _unique(items):
        seen = set()
        out = []
        for item in items:
            key = str(item).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    def _flatten_mitre(entries):
        out = []
        for m in entries:
            if isinstance(m, dict):
                out.append({
                    'technique_id': m.get('technique_id') or m.get('id') or m.get('technique'),
                    'tactics': m.get('tactics') or m.get('tactic') or []
                })
            else:
                out.append({'technique_id': str(m), 'tactics': []})
        return out

    def _flatten_iocs(entries):
        out = []
        for ioc in entries:
            if isinstance(ioc, dict):
                out.append({
                    'indicator': ioc.get('ioc') or ioc.get('indicator') or ioc.get('value'),
                    'verdict': ioc.get('verdict') or ioc.get('risk'),
                    'confidence': ioc.get('confidence') or ioc.get('confidence_score')
                })
            else:
                out.append({'indicator': str(ioc), 'verdict': None, 'confidence': None})
        return out

    context = {
        'incident': {
            'id': row.id,
            'summary': row.summary,
            'severity': row.severity,
            'decision_reason': row.decision_reason,
            'source': row.source,
            'confidence_score': row.confidence_score
        },
        'detection_rules': _unique(rule_names),
        'mitre_techniques': _flatten_mitre(mitre_entries),
        'ioc_verdicts': _flatten_iocs(ioc_entries),
        'correlation_findings': _unique([str(r).strip() for r in correlation_findings if str(r).strip()]),
        'ai_investigation': {
            'summary': investigation_payload.get('summary') or '',
            'confidence_score': investigation_payload.get('confidence_score') or ai_confidence,
            'key_reasoning': investigation_payload.get('explainability') or investigation_payload.get('assessment', {}).get('reasoning') or []
        },
        'allow_containment': bool(ai_confidence >= 80)
    }

    missing_dimensions = []
    if not context.get('detection_rules'):
        missing_dimensions.append('Detection rules')
    if not context.get('mitre_techniques'):
        missing_dimensions.append('MITRE techniques')
    if not context.get('ioc_verdicts'):
        missing_dimensions.append('IOC verdicts')
    if not context.get('correlation_findings'):
        missing_dimensions.append('Correlation findings')
    if not context.get('ai_investigation', {}).get('summary'):
        missing_dimensions.append('AI investigation summary')

    context['dimensions_missing'] = missing_dimensions

    result = await ai_service.generate_tactical_briefing(context)
    return result
