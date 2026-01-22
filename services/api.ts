import { Agent, Telemetry, Incident, Severity, AlertAnalysisResponse } from '../types';

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
  }
};
