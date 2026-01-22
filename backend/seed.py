print("🔥 seed.py started...")
from datetime import datetime
from app.database.db import SessionLocal, Base, engine
from app.models.models import Agent, Alert

# create tables (safe)
Base.metadata.create_all(bind=engine)

def seed_data():
    db = SessionLocal()

    # ----------------------------
    # Insert Agents
    # ----------------------------
    agent1 = Agent(
        agent_id="AGENT-001",
        hostname="OFFICER-PC-1",
        ip_address="192.168.1.10",
        os="Windows 11",
        last_seen=datetime.utcnow()
    )

    agent2 = Agent(
        agent_id="AGENT-002",
        hostname="OFFICER-LAPTOP-2",
        ip_address="192.168.1.11",
        os="Windows 10",
        last_seen=datetime.utcnow()
    )

    db.add(agent1)
    db.add(agent2)
    db.commit()

    # ----------------------------
    # Insert Alerts
    # ----------------------------
    alert1 = Alert(
        agent_id="AGENT-001",
        timestamp=datetime.utcnow(),
        severity="High",
        title="Suspicious Login Attempt",
        description="Multiple failed login attempts detected from unknown IP.",
        evidence_json='{"source_ip":"45.23.11.90","attempts":7}',
        status="Open"
    )

    alert2 = Alert(
        agent_id="AGENT-002",
        timestamp=datetime.utcnow(),
        severity="Medium",
        title="Possible Malware Activity",
        description="Unknown process tried to access sensitive directory.",
        evidence_json='{"process":"unknown.exe","path":"C:/Windows/System32"}',
        status="Investigating"
    )

    db.add(alert1)
    db.add(alert2)
    db.commit()

    db.close()
    print("✅ Dummy data inserted successfully!")

if __name__ == "__main__":
    seed_data()
