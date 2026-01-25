from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database.db import Base


class CorrelationFinding(Base):
    __tablename__ = "correlation_findings"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    window_start = Column(DateTime(timezone=True), index=True)
    window_end = Column(DateTime(timezone=True), index=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    confidence_score = Column(Integer, default=0)
    entities_json = Column(Text)
    evidence_json = Column(Text)
    mitre_json = Column(Text)
    ioc_json = Column(Text)
    summary_text = Column(Text)
    status = Column(String, default="open")
    fingerprint = Column(String, unique=True, index=True, nullable=False)
