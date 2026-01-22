from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class TelemetryCreate(BaseModel):
    agent_id: str = Field(..., description="Unique identifier for the agent")
    hostname: str = Field(..., description="Machine hostname")
    ip_address: str = Field(..., description="Current IP address of the agent")
    os: str = Field(..., description="Operating System of the host")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    cpu_percent: float = Field(..., ge=0, le=100)
    ram_percent: float = Field(..., ge=0, le=100)
    disk_percent: float = Field(..., ge=0, le=100)
    
    process_count: int = Field(..., ge=0)
    connection_count: int = Field(..., ge=0)
    
    processes: List[str] = Field(default_factory=list, description="List of running process names")
    connections: List[Dict[str, Any]] = Field(default_factory=list, description="List of active network connections")

class TelemetryResponse(BaseModel):
    id: int
    agent_id: str
    timestamp: datetime
    cpu_percent: float
    ram_percent: float
    disk_percent: float
    process_count: int
    connection_count: int
    raw_json: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True
