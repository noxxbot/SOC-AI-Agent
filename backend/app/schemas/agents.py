from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AgentResponse(BaseModel):
    id: int
    agent_id: str
    hostname: str
    ip_address: Optional[str]
    os: Optional[str]
    last_seen: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True
