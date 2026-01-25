from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON, Text
from sqlalchemy.sql import func
from app.database.db import Base

class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, unique=True, index=True, nullable=False)
    hostname = Column(String, nullable=False)
    ip_address = Column(String)
    os = Column(String)
    last_seen = Column(DateTime(timezone=True), onupdate=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Telemetry(Base):
    __tablename__ = "telemetry"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, ForeignKey("agents.agent_id"), nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    cpu_percent = Column(Float)
    ram_percent = Column(Float)
    disk_percent = Column(Float)
    process_count = Column(Integer)
    connection_count = Column(Integer)
    raw_json = Column(JSON)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, ForeignKey("agents.agent_id"), nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    severity = Column(String, nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    title = Column(String, nullable=False)
    description = Column(Text)
    evidence_json = Column(JSON)
    status = Column(String, default="OPEN") # OPEN, INVESTIGATING, RESOLVED

class EndpointLog(Base):
    __tablename__ = "endpoint_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    agent_id = Column(String, index=True, nullable=False)
    hostname = Column(String)
    log_source = Column(String, index=True)
    event_type = Column(String, index=True)
    severity_raw = Column(String)
    raw = Column(Text)
    fields_json = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ProcessedLog(Base):
    __tablename__ = "processed_logs"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True, nullable=False, default="unknown")
    hostname = Column(String, default="unknown")
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    category = Column(String, index=True, default="other")
    event_type = Column(String, index=True, default="other")
    severity_score = Column(Integer, default=0)
    message = Column(Text)
    raw = Column(Text)
    fields_json = Column(Text)
    iocs_json = Column(Text)
    tags_json = Column(Text)
    fingerprint = Column(String, index=True, unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
