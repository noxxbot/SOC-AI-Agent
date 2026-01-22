from pydantic import BaseModel, Field
from typing import List, Dict, Optional

class LogAnalysisRequest(BaseModel):
    logs: str = Field(..., description="The raw log content to analyze")

class ThreatVectors(BaseModel):
    persistence: int
    lateralMovement: int
    exfiltration: int
    reconnaissance: int
    credentialAccess: int

class LogAnalysisResponse(BaseModel):
    riskScore: int
    threatDetected: bool
    explanation: str
    recommendations: List[str]
    threatVectors: ThreatVectors

class AlertAnalysisRequest(BaseModel):
    alert_id: int = Field(..., description="ID of the alert to analyze")

class AlertAnalysisResponse(BaseModel):
    riskScore: int = Field(..., description="Risk score from 0-100")
    explanation: str = Field(..., description="Technical explanation of the findings")
    recommendedActions: List[str] = Field(..., description="List of remediation steps")
    mitreMapping: List[str] = Field(..., description="List of MITRE ATT&CK techniques")