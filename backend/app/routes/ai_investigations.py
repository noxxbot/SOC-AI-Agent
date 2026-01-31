from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import json

from app.database.db import get_db
from app.models.ai_investigation import AIInvestigation
from app.models.detection_alert import DetectionAlert
from app.services.ai_service import AIService
from app.services.alert_automation import (
    run_ai_investigation_and_maybe_create_incident,
    run_ai_investigation_and_maybe_create_incident_task
)

router = APIRouter()
ai_service = AIService()


class InvestigationRunRequest(BaseModel):
    force: bool = False


class InvestigationBulkRequest(BaseModel):
    alert_ids: Optional[List[int]] = None
    limit: int = Field(50, ge=1, le=500)
    severity: Optional[str] = None
    force: bool = False


class InvestigationRecord(BaseModel):
    id: int
    created_at: Optional[str]
    alert_id: int
    model_name: str
    prompt_hash: str
    investigation: Dict[str, Any]
    output_json: Dict[str, Any]
    confidence_score: int
    is_incident: bool
    incident_severity: str
    status: str
    error_message: Optional[str]
    failure_reason: Optional[str] = None
    retry_count: Optional[int]
    last_retry_reason: Optional[str]
    raw_response: Optional[str] = ""
    summary: Optional[str]


def _parse_json(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _default_investigation_payload() -> Dict[str, Any]:
    return {
        "summary": "AI failed – manual review needed.",
        "case_notes": "AI failed – manual review needed.",
        "explainability": [
            "AI output was unavailable for this investigation.",
            "No additional evidence could be evaluated.",
            "Investigation requires manual review.",
            "Additional telemetry is needed for validation."
        ],
        "assessment": {
            "is_incident": False,
            "incident_severity": "none",
            "confidence_score": 0,
            "reasoning": "AI output was unavailable; manual review required."
        },
        "recommended_actions": [
            "Review alert evidence manually.",
            "Collect additional telemetry for validation.",
            "Monitor for related activity."
        ],
        "ioc_analysis": {
            "observed_iocs": [],
            "ioc_verdict": "unknown",
            "ioc_notes": "No IOC analysis available."
        },
        "mitre_analysis": {
            "techniques": [],
            "tactics": [],
            "mitre_notes": "No MITRE analysis available."
        },
        "timeline": [
            "Step 1: Alert triggered and AI investigation started.",
            "Step 2: AI output unavailable for analysis.",
            "Step 3: Manual investigation recommended."
        ],
        "mitre_mapping": [],
        "ioc_verdicts": [],
        "confidence_score": 0,
        "is_incident": False,
        "incident_severity": "none",
        "confidence_breakdown": {}
    }


def _row_to_dict(row: AIInvestigation) -> Dict[str, Any]:
    output_json = _parse_json(row.investigation_json, {}) or {}
    if not isinstance(output_json, dict):
        output_json = {}
    if not output_json:
        output_json = _default_investigation_payload()
    created_at = _ensure_utc(row.created_at)
    return {
        "id": row.id,
        "alert_id": row.alert_id,
        "created_at": created_at.isoformat() if created_at else None,
        "status": row.status,
        "error_message": row.error_message,
        "failure_reason": row.failure_reason,
        "retry_count": row.retry_count,
        "last_retry_reason": row.last_retry_reason,
        "raw_response": row.raw_response,
        "output_json": output_json,
        "model_name": row.model_name,
        "prompt_hash": row.prompt_hash,
        "confidence_score": row.confidence_score,
        "is_incident": bool(row.is_incident),
        "incident_severity": row.incident_severity
    }


def _map_investigation(row_data: Dict[str, Any]) -> Dict[str, Any]:
    output_json = row_data.get("output_json") or {}
    if not isinstance(output_json, dict):
        output_json = {}
    if not output_json:
        output_json = _default_investigation_payload()
    summary = output_json.get("summary")
    confidence_score = output_json.get("confidence_score", row_data.get("confidence_score", 0))
    is_incident = output_json.get("is_incident", row_data.get("is_incident", False))
    incident_severity = output_json.get("incident_severity", row_data.get("incident_severity", "none"))
    payload = {
        "id": row_data.get("id"),
        "created_at": row_data.get("created_at"),
        "alert_id": row_data.get("alert_id"),
        "model_name": row_data.get("model_name"),
        "prompt_hash": row_data.get("prompt_hash"),
        "investigation": output_json,
        "output_json": output_json,
        "confidence_score": confidence_score,
        "is_incident": bool(is_incident),
        "incident_severity": incident_severity,
        "status": row_data.get("status"),
        "error_message": row_data.get("error_message"),
        "failure_reason": row_data.get("failure_reason"),
        "retry_count": row_data.get("retry_count"),
        "last_retry_reason": row_data.get("last_retry_reason"),
        "raw_response": row_data.get("raw_response"),
        "summary": summary
    }
    return _normalize_investigation_response(payload)


def _normalize_investigation_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_json = payload.get("output_json") or payload.get("investigation") or {}
    default_payload = _default_investigation_payload()
    if not isinstance(output_json, dict) or not output_json:
        output_json = default_payload
    else:
        for key, value in default_payload.items():
            output_json.setdefault(key, value)
    status = str(payload.get("status") or "").strip().lower()
    error_message = payload.get("error_message")
    failure_reason = payload.get("failure_reason")
    if status == "failed":
        if not failure_reason:
            failure_reason = error_message
    else:
        failure_reason = None
    raw_response = payload.get("raw_response") or ""
    summary = output_json.get("summary") or default_payload.get("summary")
    payload.update(
        {
            "investigation": output_json,
            "output_json": output_json,
            "raw_response": raw_response,
            "failure_reason": failure_reason,
            "summary": summary
        }
    )
    return payload


@router.post("/ai/investigations/run/{alert_id}", response_model=InvestigationRecord)
async def run_investigation(alert_id: int, payload: InvestigationRunRequest, db: Session = Depends(get_db)):
    alert = db.query(DetectionAlert).filter(DetectionAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Detection alert not found")
    try:
        await run_ai_investigation_and_maybe_create_incident(alert.id, payload.force)
    except Exception as exc:
        failed = AIInvestigation(
            alert_id=alert.id,
            model_name="unknown",
            prompt_hash=f"failed-{alert.id}",
            investigation_json=json.dumps(_default_investigation_payload()),
            confidence_score=0,
            is_incident=False,
            incident_severity="none",
            status="failed",
            error_message=str(exc),
            failure_reason=str(exc)
        )
        db.add(failed)
        db.commit()
        db.refresh(failed)
        return _map_investigation(_row_to_dict(failed))

    row = (
        db.query(AIInvestigation)
        .filter(AIInvestigation.alert_id == alert.id)
        .order_by(AIInvestigation.created_at.desc())
        .first()
    )
    if row:
        return _map_investigation(_row_to_dict(row))
    failed = AIInvestigation(
        alert_id=alert.id,
        model_name="unknown",
        prompt_hash=f"failed-{alert.id}",
        investigation_json=json.dumps(_default_investigation_payload()),
        confidence_score=0,
        is_incident=False,
        incident_severity="none",
        status="failed",
        error_message="AI investigation failed",
        failure_reason="AI investigation failed"
    )
    db.add(failed)
    db.commit()
    db.refresh(failed)
    return _map_investigation(_row_to_dict(failed))


@router.get("/ai/investigations/alerts/{alert_id}", response_model=List[InvestigationRecord])
def list_investigations(alert_id: int, db: Session = Depends(get_db)):
    rows = (
        db.query(AIInvestigation)
        .filter(AIInvestigation.alert_id == alert_id)
        .order_by(AIInvestigation.created_at.desc())
        .all()
    )
    return [_map_investigation(_row_to_dict(r)) for r in rows]


@router.post("/ai/investigations/run-bulk", response_model=Dict[str, Any])
async def run_investigations_bulk(
    payload: InvestigationBulkRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    alerts: List[DetectionAlert] = []
    if payload.alert_ids:
        alerts = db.query(DetectionAlert).filter(DetectionAlert.id.in_(payload.alert_ids)).all()
    else:
        query = db.query(DetectionAlert).order_by(DetectionAlert.created_at.desc())
        if payload.severity:
            query = query.filter(DetectionAlert.severity == payload.severity)
        alerts = query.limit(payload.limit).all()

    scheduled = 0
    for alert in alerts:
        background_tasks.add_task(run_ai_investigation_and_maybe_create_incident_task, alert.id, payload.force)
        scheduled += 1

    return {"status": "ok", "scheduled": scheduled}


@router.get("/ai/test", response_model=Dict[str, Any])
async def test_ai():
    prompt = 'Say hello in JSON {"msg":"hello"}'
    raw_response = await ai_service._ask_ollama(prompt)
    cleaned = ai_service._clean_llm_output(raw_response)
    parsed = ai_service._extract_json_from_text(cleaned) or {}
    error_message = None if parsed else "invalid_json"
    return {
        "prompt": prompt,
        "raw_response": raw_response,
        "cleaned": cleaned,
        "parsed": parsed,
        "error_message": error_message
    }
