
import time
import json
import socket
import platform
import psutil
import requests
import os
import uuid
from datetime import datetime, timezone

def get_config():
    """Loads agent configuration from config.json."""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("Error: config.json not found. Using default values.")
        return {
            "backend_url": "http://localhost:8000/api/v1/telemetry",
            "agent_id": "DEFAULT-AGENT"
        }

def get_local_ip():
    """Retrieves the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Using a non-routable address to find the interface used for internet access
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def collect_telemetry(agent_id):
    """Gathers system metrics and metadata."""
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()}"
    ip_address = get_local_ip()

    # Hardware Utilization
    cpu_percent = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    # Process Inventory
    processes = []
    for proc in psutil.process_iter(['name']):
        try:
            processes.append(proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    process_count = len(processes)

    # Network Connections
    connections_data = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:
                connections_data.append({
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port
                })
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        # Some OS require elevation to list all connections
        pass
    
    connection_count = len(connections_data)

    return {
        "agent_id": agent_id,
        "hostname": hostname,
        "ip_address": ip_address,
        "os": os_info,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": float(cpu_percent),
        "ram_percent": float(ram.percent),
        "disk_percent": float(disk.percent),
        "process_count": process_count,
        "connection_count": connection_count,
        "processes": processes[:100],  # Sending first 100 process names
        "connections": connections_data[:100]  # Sending first 100 remote connections
    }

def generate_event(agent_id, hostname, log_source, event_type, severity_raw, raw, fields):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "hostname": hostname,
        "log_source": log_source,
        "event_type": event_type,
        "severity_raw": severity_raw,
        "raw": raw,
        "fields": fields or {}
    }

def collect_structured_logs(telemetry):
    logs = []
    agent_id = telemetry.get("agent_id")
    hostname = telemetry.get("hostname")

    cpu_percent = telemetry.get("cpu_percent")
    ram_percent = telemetry.get("ram_percent")

    try:
        if cpu_percent is not None and cpu_percent > 90:
            logs.append(
                generate_event(
                    agent_id,
                    hostname,
                    "performance",
                    "cpu_high",
                    "high",
                    f"CPU usage high: {cpu_percent}%",
                    {"cpu_percent": float(cpu_percent)}
                )
            )
        if ram_percent is not None and ram_percent > 90:
            logs.append(
                generate_event(
                    agent_id,
                    hostname,
                    "performance",
                    "ram_high",
                    "high",
                    f"RAM usage high: {ram_percent}%",
                    {"ram_percent": float(ram_percent)}
                )
            )
    except Exception:
        pass

    suspicious_processes = {"powershell", "cmd.exe", "bash", "sh", "python", "nc", "netcat"}
    try:
        for proc in psutil.process_iter(['name', 'pid', 'username', 'cmdline']):
            try:
                name = (proc.info.get("name") or "").lower()
                if name and name in suspicious_processes:
                    cmdline = proc.info.get("cmdline") or []
                    raw = f"Process start: {proc.info.get('name')}"
                    logs.append(
                        generate_event(
                            agent_id,
                            hostname,
                            "process",
                            "process_start",
                            "warn",
                            raw,
                            {
                                "process_name": proc.info.get("name"),
                                "pid": proc.info.get("pid"),
                                "username": proc.info.get("username"),
                                "command_line": " ".join(cmdline) if cmdline else None
                            }
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        pass

    try:
        for conn in psutil.net_connections(kind='inet'):
            try:
                if not conn.raddr:
                    continue
                local_ip = conn.laddr.ip if conn.laddr else None
                local_port = conn.laddr.port if conn.laddr else None
                remote_ip = conn.raddr.ip if conn.raddr else None
                remote_port = conn.raddr.port if conn.raddr else None
                protocol = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                state = conn.status if conn.status else None
                raw = f"Network connection {local_ip}:{local_port} -> {remote_ip}:{remote_port}"
                logs.append(
                    generate_event(
                        agent_id,
                        hostname,
                        "network",
                        "net_conn",
                        "info",
                        raw,
                        {
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "protocol": protocol,
                            "state": state
                        }
                    )
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
    except Exception:
        pass

    return logs

def safe_post(url, payload):
    try:
        response = requests.post(url, json=payload, timeout=10)
        return response
    except requests.exceptions.RequestException:
        return None

def main():
    config = get_config()
    backend_url = config.get("backend_url")
    agent_id = config.get("agent_id")
    interval_seconds = int(config.get("interval_seconds", 5))
    
    print(f"Kavach AI Agent [{agent_id}] initialized.")
    print(f"Target Backend: {backend_url}")
    print("Monitoring active... Press Ctrl+C to stop.")

    while True:
        try:
            telemetry_payload = collect_telemetry(agent_id)
            logs = []
            try:
                logs = collect_structured_logs(telemetry_payload)
            except Exception:
                logs = []

            payload = {
                "agent_id": telemetry_payload.get("agent_id"),
                "hostname": telemetry_payload.get("hostname"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "telemetry": telemetry_payload,
                "logs": logs
            }

            response = safe_post(backend_url, payload)
            
            if response and response.status_code == 200:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Sent {len(logs)} logs + telemetry to backend")
            elif response:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Failed to send telemetry: Status {response.status_code}")
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Failed to send telemetry: Connection error (Backend potentially down)")
                
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Internal Error: {str(e)}")

        time.sleep(interval_seconds)

if __name__ == "__main__":
    main()
