from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.models.models import Alert
from app.schemas.alerts import AlertCreate, AlertResponse
from app.services.notification_service import manager
from typing import List
import json

router = APIRouter()

@router.post("/alerts", response_model=AlertResponse)
async def create_alert(alert_data: AlertCreate, db: Session = Depends(get_db)):
    """
    Creates a new security alert and broadcasts it via WebSocket.
    """
    new_alert = Alert(
        agent_id=alert_data.agent_id,
        severity=alert_data.severity,
        title=alert_data.title,
        description=alert_data.description,
        evidence_json=alert_data.evidence_json,
        status="OPEN"
    )
    
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)
    
    # Prepare broadcast payload
    payload = {
        "type": "NEW_ALERT",
        "data": {
            "id": new_alert.id,
            "title": new_alert.title,
            "severity": new_alert.severity,
            "agent_id": new_alert.agent_id
        }
    }
    
    # Broadcast to all connected clients
    await manager.broadcast(payload)
    
    return new_alert

@router.get("/alerts", response_model=List[AlertResponse])
def get_alerts(db: Session = Depends(get_db)):
    """
    Lists all security alerts sorted by most recent.
    """
    return db.query(Alert).order_by(Alert.timestamp.desc()).all()

@router.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    """
    Retrieves detailed information for a specific security alert.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
