from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Any, Dict, List, Optional
import json

from app.core.config import settings
from app.database.db import get_db
from app.models.detection_alert import DetectionAlert
from app.models.ai_investigation import AIInvestigation
from app.services.alert_automation import (
    schedule_ai_investigation,
    build_investigation_context,
    compute_confidence_breakdown
)
from app.services.rule_engine import run_rule_engine

router = APIRouter()


class DetectionAlertResponse(BaseModel):
    """
    Response schema for detection alerts.
    """
    id: int
    created_at: Optional[str]
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    confidence_score: int
    confidence_breakdown: Dict[str, Any]
    confidence_explanation: Optional[str]
    category: str
    status: str
    summary: Optional[str]
    evidence: Dict[str, Any]
    mitre: List[Dict[str, Any]]
    ioc_matches: List[Dict[str, Any]]
    recommended_actions: List[str]
    fingerprint: str
    investigated: bool
    incident_id: Optional[int]


def _parse_json(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _map_alert(alert: DetectionAlert, investigated: bool = False) -> Dict[str, Any]:
    evidence = _parse_json(alert.evidence_json, {})
    confidence_breakdown = evidence.get("confidence_breakdown") or {}
    confidence_explanation = evidence.get("confidence_explanation") or ""
    incident_id = evidence.get("incident_id")
    if isinstance(incident_id, str) and incident_id.isdigit():
        incident_id = int(incident_id)
    if isinstance(incident_id, bool):
        incident_id = None
    return {
        "id": alert.id,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "alert_id": evidence.get("alert_id") or f"DET-{alert.id}",
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "confidence_score": alert.confidence_score,
        "confidence_breakdown": confidence_breakdown,
        "confidence_explanation": confidence_explanation,
        "category": alert.category,
        "status": alert.status,
        "summary": alert.summary,
        "evidence": evidence,
        "mitre": _parse_json(alert.mitre_json, []),
        "ioc_matches": _parse_json(alert.ioc_json, []),
        "recommended_actions": _parse_json(alert.actions_json, []),
        "fingerprint": alert.fingerprint,
        "investigated": investigated,
        "incident_id": incident_id
    }


@router.post("/detections/run", response_model=Dict[str, Any])
def run_detections(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    result = run_rule_engine()
    alerts = result.get("alerts", [])
    fingerprints = [a.get("fingerprint") for a in alerts if a.get("fingerprint")]
    existing = set()
    if fingerprints:
        rows = db.query(DetectionAlert.fingerprint).filter(DetectionAlert.fingerprint.in_(fingerprints)).all()
        existing = {r[0] for r in rows}

    to_insert: List[DetectionAlert] = []
    skipped_duplicates = 0
    for alert in alerts:
        fingerprint = alert.get("fingerprint")
        if not fingerprint or fingerprint in existing:
            skipped_duplicates += 1
            continue
        evidence = alert.get("evidence") or {}
        to_insert.append(
            DetectionAlert(
                rule_id=alert.get("rule_id") or "RULE-UNKNOWN",
                rule_name=alert.get("rule_name") or "Unnamed Rule",
                severity=alert.get("severity") or "medium",
                confidence_score=int(alert.get("confidence_score") or 0),
                category=alert.get("category") or "general",
                status=alert.get("status") or "open",
                summary=alert.get("summary") or evidence.get("summary"),
                evidence_json=json.dumps(evidence),
                mitre_json=json.dumps(alert.get("mitre") or []),
                ioc_json=json.dumps(alert.get("ioc_matches") or []),
                actions_json=json.dumps(alert.get("recommended_actions") or []),
                fingerprint=fingerprint
            )
        )

    created = 0
    created_alerts: List[DetectionAlert] = []
    if to_insert:
        try:
            db.add_all(to_insert)
            db.commit()
            created = len(to_insert)
            created_alerts = list(to_insert)
        except IntegrityError:
            db.rollback()
            for item in to_insert:
                try:
                    db.add(item)
                    db.commit()
                    created += 1
                    created_alerts.append(item)
                except IntegrityError:
                    db.rollback()
                    skipped_duplicates += 1

    for alert in created_alerts:
        context = build_investigation_context(db, alert)
        confidence = compute_confidence_breakdown(alert, context, context.get("ai_investigation") or {})
        evidence = _parse_json(alert.evidence_json, {})
        evidence.update(
            {
                "confidence_breakdown": confidence.get("confidence_breakdown") or {},
                "confidence_explanation": confidence.get("confidence_explanation") or "",
                "confidence_floor_applied": bool(confidence.get("confidence_floor_applied"))
            }
        )
        alert.evidence_json = json.dumps(evidence)
        alert.confidence_score = int(confidence.get("confidence_score") or 0)
        db.add(alert)
        db.commit()
        schedule_ai_investigation(alert.id, db, background_tasks, False)

    return {
        "status": "ok",
        "processed_logs_checked": result.get("processed_logs_checked", 0),
        "correlation_findings_checked": result.get("correlation_findings_checked", 0),
        "alerts_created": created,
        "alerts_skipped_duplicates": skipped_duplicates
    }


@router.get("/detections/alerts", response_model=List[DetectionAlertResponse])
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    alerts = (
        db.query(DetectionAlert)
        .order_by(DetectionAlert.created_at.desc())
        .limit(limit)
        .all()
    )
    alert_ids = [a.id for a in alerts]
    investigated_ids = set()
    if alert_ids:
        rows = (
            db.query(AIInvestigation.alert_id)
            .filter(
                AIInvestigation.alert_id.in_(alert_ids),
                AIInvestigation.status.in_(["completed", "failed", "running"])
            )
            .distinct()
            .all()
        )
        investigated_ids = {row[0] for row in rows}
    return [_map_alert(a, a.id in investigated_ids) for a in alerts]


@router.get("/detections/alerts/{alert_id}", response_model=DetectionAlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(DetectionAlert).filter(DetectionAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Detection alert not found")
    investigated = (
        db.query(AIInvestigation.id)
        .filter(
            AIInvestigation.alert_id == alert.id,
            AIInvestigation.status.in_(["completed", "failed", "running"])
        )
        .first()
        is not None
    )
    return _map_alert(alert, investigated)
