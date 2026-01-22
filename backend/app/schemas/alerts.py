from pydantic import BaseModel
from typing import Optional, Any
from datetime import datetime

class AlertCreate(BaseModel):
    agent_id: str
    severity: str
    title: str
    description: Optional[str] = None
    evidence_json: Optional[Any] = None

class AlertResponse(BaseModel):
    id: int
    agent_id: str
    timestamp: datetime
    severity: str
    title: str
    description: Optional[str]
    evidence_json: Optional[Any]
    status: str

    class Config:
        from_attributes = True
