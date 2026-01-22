
import time
import json
import socket
import platform
import psutil
import requests
import os
from datetime import datetime

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
        "timestamp": datetime.utcnow().isoformat(),
        "cpu_percent": float(cpu_percent),
        "ram_percent": float(ram.percent),
        "disk_percent": float(disk.percent),
        "process_count": process_count,
        "connection_count": connection_count,
        "processes": processes[:100],  # Sending first 100 process names
        "connections": connections_data[:100]  # Sending first 100 remote connections
    }

def main():
    config = get_config()
    backend_url = config.get("backend_url")
    agent_id = config.get("agent_id")
    
    print(f"Sentinel AI Agent [{agent_id}] initialized.")
    print(f"Target Backend: {backend_url}")
    print("Monitoring active... Press Ctrl+C to stop.")

    while True:
        try:
            telemetry_payload = collect_telemetry(agent_id)
            
            response = requests.post(
                backend_url, 
                json=telemetry_payload, 
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Sent telemetry successfully")
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Failed to send telemetry: Status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Failed to send telemetry: Connection error (Backend potentially down)")
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Internal Error: {str(e)}")

        # Wait for 15 seconds before the next collection cycle
        time.sleep(15)

if __name__ == "__main__":
    main()
