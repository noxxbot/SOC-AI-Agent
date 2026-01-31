from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.sql import func
from app.database.db import Base


class AIInvestigation(Base):
    __tablename__ = "ai_investigations"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    alert_id = Column(Integer, ForeignKey("detection_alerts.id"), index=True, nullable=False)
    model_name = Column(String, nullable=False)
    prompt_hash = Column(String, index=True, nullable=False)
    investigation_json = Column(Text)
    investigation_text = Column(Text)
    confidence_score = Column(Integer, default=0)
    is_incident = Column(Boolean, default=False)
    incident_severity = Column(String, default="low")
    status = Column(String, default="pending")
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    last_retry_reason = Column(Text)
    failure_reason = Column(Text)
    raw_response = Column(Text)
