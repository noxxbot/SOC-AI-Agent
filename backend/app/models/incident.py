from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database.db import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    title = Column(String, nullable=False)
    summary = Column(Text)
    severity = Column(String, nullable=False)
    confidence_score = Column(Integer, default=0)
    incident_fingerprint = Column(String, unique=True, index=True, nullable=False)
    source = Column(String, default="rule_engine")
    agent_id = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    primary_iocs_json = Column(Text)
    mitre_techniques_json = Column(Text)
    related_alert_ids_json = Column(Text)
    related_log_fingerprints_json = Column(Text)
    decision_reason = Column(Text)
