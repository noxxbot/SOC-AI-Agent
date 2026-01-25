from typing import Any, Dict, List
from pydantic import BaseModel, Field


class IOCSet(BaseModel):
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    sha256: List[str] = Field(default_factory=list)
    md5: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)


class MitreHint(BaseModel):
    technique_id: str
    name: str
    confidence: float


class MitreMatch(BaseModel):
    technique_id: str
    technique_name: str
    tactics: List[str] = Field(default_factory=list)
    confidence_score: int
    reasoning: str
    matched_signals: List[str] = Field(default_factory=list)


class IOCSummary(BaseModel):
    risk: str
    confidence: int
    notes: str


class IOCMatch(BaseModel):
    ioc: str
    type: str
    verdict: str
    source: str
    details: str


class IOCIntel(BaseModel):
    ioc_summary: IOCSummary
    ioc_matches: List[IOCMatch] = Field(default_factory=list)


class NormalizedLog(BaseModel):
    event_id: str
    agent_id: str
    hostname: str
    timestamp: str
    log_source: str
    event_type: str
    category: str
    severity_raw: str
    severity_score: int
    message: str
    raw: str
    fields: Dict[str, Any] = Field(default_factory=dict)


class EnrichedLog(NormalizedLog):
    iocs: IOCSet = Field(default_factory=IOCSet)
    mitre_hints: List[MitreHint] = Field(default_factory=list)
    mitre_matches: List[MitreMatch] = Field(default_factory=list)
    ioc_intel: IOCIntel = Field(default_factory=lambda: IOCIntel(ioc_summary=IOCSummary(risk="unknown", confidence=0, notes="")))
    tags: List[str] = Field(default_factory=list)
    fingerprint: str
