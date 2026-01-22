from sqlalchemy.orm import Session
from app.models.models import Alert
from app.schemas.telemetry import TelemetryCreate
from app.services.notification_service import manager
import json

class DetectionEngine:
    async def run_checks(self, db: Session, data: TelemetryCreate):
        """
        Runs a set of security rules against the ingested telemetry data.
        Returns a list of triggered alerts.
        """
        triggered_alerts = []

        # Rule 1: High CPU Usage
        if data.cpu_percent > 90:
            triggered_alerts.append({
                "severity": "MEDIUM",
                "title": "High CPU Utilization",
                "description": f"Agent {data.hostname} is reporting sustained CPU usage of {data.cpu_percent}%.",
                "evidence": {"cpu_percent": data.cpu_percent}
            })

        # Rule 2: High Connection Count
        if data.connection_count > 200:
            triggered_alerts.append({
                "severity": "HIGH",
                "title": "Network Connection Spike",
                "description": f"Excessive outbound/inbound connections detected ({data.connection_count}). Potential DDoS or scanning activity.",
                "evidence": {"connection_count": data.connection_count}
            })

        # Rule 3: Suspicious Process Execution
        suspicious_procs = [p for p in data.processes if "powershell" in p.lower() or "cmd.exe" in p.lower()]
        if suspicious_procs:
            triggered_alerts.append({
                "severity": "MEDIUM",
                "title": "Suspicious Shell Execution",
                "description": f"Detected execution of administrative shells: {', '.join(suspicious_procs)}",
                "evidence": {"processes": suspicious_procs}
            })

        # Rule 4: Malicious Ports
        malicious_ports = [4444, 1337]
        suspicious_conns = [c for c in data.connections if c.get("remote_port") in malicious_ports]
        if suspicious_conns:
            triggered_alerts.append({
                "severity": "HIGH",
                "title": "Known Malicious Port Connection",
                "description": f"Connection detected to ports often associated with Metasploit/Backdoors ({', '.join(map(str, malicious_ports))}).",
                "evidence": {"connections": suspicious_conns}
            })

        # Persist and Broadcast
        saved_alerts = []
        for alert_dict in triggered_alerts:
            new_alert = Alert(
                agent_id=data.agent_id,
                severity=alert_dict["severity"],
                title=alert_dict["title"],
                description=alert_dict["description"],
                evidence_json=alert_dict["evidence"],
                status="OPEN"
            )
            db.add(new_alert)
            db.commit()
            db.refresh(new_alert)
            
            # Broadcast to UI
            payload = {
                "type": "NEW_ALERT",
                "data": {
                    "id": new_alert.id,
                    "title": new_alert.title,
                    "severity": new_alert.severity,
                    "agent_id": new_alert.agent_id
                }
            }
            await manager.broadcast(payload)
            saved_alerts.append(new_alert)

        return saved_alerts

detection_engine = DetectionEngine()
