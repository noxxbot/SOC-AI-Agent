from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.models.models import Agent, Telemetry
from app.schemas.telemetry import TelemetryCreate, TelemetryResponse
from app.services.detection_engine import detection_engine
from sqlalchemy.sql import func
from typing import List

router = APIRouter()

@router.post("/telemetry")
async def ingest_telemetry(data: TelemetryCreate, db: Session = Depends(get_db)):
    """
    Ingests real-time telemetry from a SOC-AI agent.
    If the agent is unknown, it registers it automatically.
    Triggers the detection engine for real-time alerting.
    """
    try:
        # 1. Check if agent exists, otherwise create it
        agent = db.query(Agent).filter(Agent.agent_id == data.agent_id).first()
        
        if not agent:
            agent = Agent(
                agent_id=data.agent_id,
                hostname=data.hostname,
                ip_address=data.ip_address,
                os=data.os,
                last_seen=func.now()
            )
            db.add(agent)
        else:
            # Update agent heartbeat and basic info
            agent.hostname = data.hostname
            agent.ip_address = data.ip_address
            agent.os = data.os
            agent.last_seen = func.now()

        # 2. Store telemetry record
        new_telemetry = Telemetry(
            agent_id=data.agent_id,
            timestamp=data.timestamp,
            cpu_percent=data.cpu_percent,
            ram_percent=data.ram_percent,
            disk_percent=data.disk_percent,
            process_count=data.process_count,
            connection_count=data.connection_count,
            raw_json={
                "processes": data.processes,
                "connections": data.connections
            }
        )
        
        db.add(new_telemetry)
        db.commit()
        db.refresh(new_telemetry)

        # 3. Run Detection Engine
        alerts_triggered = await detection_engine.run_checks(db, data)
        
        return {
            "message": "telemetry stored",
            "agent_id": data.agent_id,
            "telemetry_id": new_telemetry.id,
            "alerts_triggered": [
                {"id": a.id, "title": a.title, "severity": a.severity} for a in alerts_triggered
            ]
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to ingest telemetry: {str(e)}")

@router.get("/telemetry/{agent_id}", response_model=List[TelemetryResponse])
def get_agent_telemetry(
    agent_id: str, 
    limit: int = Query(50, ge=1, le=500), 
    db: Session = Depends(get_db)
):
    """
    Retrieves the latest telemetry snapshots for a specific agent.
    """
    telemetry = db.query(Telemetry)\
        .filter(Telemetry.agent_id == agent_id)\
        .order_by(Telemetry.timestamp.desc())\
        .limit(limit)\
        .all()
    return telemetry
