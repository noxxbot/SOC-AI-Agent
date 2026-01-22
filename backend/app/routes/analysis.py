from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.models.models import Alert, Telemetry
from app.schemas.analysis import (
    LogAnalysisRequest, 
    LogAnalysisResponse, 
    AlertAnalysisRequest, 
    AlertAnalysisResponse
)
from app.services.ai_service import AIService

router = APIRouter()
ai_service = AIService()

@router.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_logs(request: LogAnalysisRequest):
    """
    Analyzes raw logs for security threats using Gemini AI.
    """
    try:
        result = await ai_service.analyze_security_logs(request.logs)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ai/analyze-alert", response_model=AlertAnalysisResponse)
async def analyze_alert_endpoint(request: AlertAnalysisRequest, db: Session = Depends(get_db)):
    """
    Fetches alert and telemetry context then performs deep AI analysis.
    """
    # 1. Fetch Alert
    alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # 2. Fetch recent telemetry for context (last 30 snapshots)
    telemetry = db.query(Telemetry)\
        .filter(Telemetry.agent_id == alert.agent_id)\
        .order_by(Telemetry.timestamp.desc())\
        .limit(30)\
        .all()
    
    # 3. Format data for AI
    alert_context = {
        "title": alert.title,
        "severity": alert.severity,
        "description": alert.description,
        "evidence": alert.evidence_json,
        "status": alert.status
    }
    
    telemetry_context = [
        {
            "timestamp": t.timestamp.isoformat(),
            "cpu_percent": t.cpu_percent,
            "ram_percent": t.ram_percent,
            "process_count": t.process_count,
            "connection_count": t.connection_count,
            "details": t.raw_json
        } for t in telemetry
    ]
    
    # 4. Perform Analysis
    try:
        result = await ai_service.analyze_alert_data(alert_context, telemetry_context)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")
