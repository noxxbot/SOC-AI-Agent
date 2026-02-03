import { Agent, Telemetry, Incident, Severity, AlertAnalysisResponse, ProcessedLog, Alert, Investigation } from '../types';

// ✅ Use 127.0.0.1 for stability (avoid localhost mismatch issues)
const BASE_URL = 'http://127.0.0.1:8000/api/v1';

// ✅ Helper (doesn't break old code, just makes debugging better)
async function fetchJson(url: string, options?: RequestInit) {
  const res = await fetch(url, options);

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API Error ${res.status}: ${text}`);
  }

  return res.json();
}

export const api = {
  async getHealth(): Promise<any> {
    return fetchJson(`${BASE_URL}/health`);
  },

  async getAgents(): Promise<Agent[]> {
    return fetchJson(`${BASE_URL}/agents`);
  },

  async getAlerts(): Promise<Incident[]> {
    const data = await fetchJson(`${BASE_URL}/alerts`);

    // Map backend Alert model to Frontend Incident model
    return data.map((alert: any) => ({
      id: `ALR-${alert.id}`,
      agentId: alert.agent_id,
      title: alert.title,
      timestamp: new Date(alert.timestamp).toLocaleString(),
      severity: alert.severity as Severity,
      status: alert.status,
      source: `Agent: ${alert.agent_id}`,
      summary: alert.description
    }));
  },

  // ✅ Threat Intel Search (simple)
  async threatIntelSearch(query: string): Promise<any> {
    return fetchJson(`${BASE_URL}/threat-intel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });
  },

  // ✅ Threat Intel Correlation (REAL correlation endpoint)
  async threatIntelCorrelate(query: string): Promise<any> {
    return fetchJson(`${BASE_URL}/threat-intel/correlate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });
  },

  async getAlertDetail(id: number): Promise<any> {
    return fetchJson(`${BASE_URL}/alerts/${id}`);
  },

  async getTelemetry(agent_id: string, limit: number = 50): Promise<Telemetry[]> {
    return fetchJson(`${BASE_URL}/telemetry/${agent_id}?limit=${limit}`);
  },

  async analyzeAlert(alert_id: number): Promise<AlertAnalysisResponse> {
    return fetchJson(`${BASE_URL}/ai/analyze-alert`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id })
    });
  },

  // ✅ Analyze raw logs using local LLM backend
  async analyzeLogs(logs: string): Promise<any> {
    return fetchJson(`${BASE_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logs })
    });
  },

  async getProcessedLogs(limit: number = 100, include_ai: boolean = false): Promise<ProcessedLog[]> {
    const aiParam = include_ai ? '&include_ai=true' : '';
    return fetchJson(`${BASE_URL}/logs/processed/recent?limit=${limit}${aiParam}`);
  },

  async getProcessedLog(id: number): Promise<ProcessedLog> {
    return fetchJson(`${BASE_URL}/logs/processed/${id}`);
  },

  async getDetectionAlerts(limit: number = 100): Promise<Alert[]> {
    return fetchJson(`${BASE_URL}/detections/alerts?limit=${limit}`);
  },

  async getDetectionAlert(id: number): Promise<Alert> {
    return fetchJson(`${BASE_URL}/detections/alerts/${id}`);
  },

  async runDetections(): Promise<any> {
    return fetchJson(`${BASE_URL}/detections/run`, { method: 'POST' });
  },

  async runInvestigation(alert_id: number, force: boolean = true): Promise<Investigation> {
    return fetchJson(`${BASE_URL}/ai/investigations/run/${alert_id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ force })
    });
  },

  async getInvestigations(alert_id: number): Promise<Investigation[]> {
    return fetchJson(`${BASE_URL}/ai/investigations/alerts/${alert_id}`);
  },

  async getRecentIncidents(limit: number = 20): Promise<Incident[]> {
    return fetchJson(`${BASE_URL}/incidents/recent?limit=${limit}`);
  },

  async getIncident(incident_id: number): Promise<Incident> {
    return fetchJson(`${BASE_URL}/incidents/${incident_id}`);
  },

  async getIncidentTacticalBriefing(incident_id: number): Promise<any> {
    return fetchJson(`${BASE_URL}/incidents/${incident_id}/tactical-briefing`, { method: 'POST' });
  }
};
