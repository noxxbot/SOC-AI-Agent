
export enum Severity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface Incident {
  id: string;
  agentId: string; // Explicit agent identifier
  title: string;
  timestamp: string;
  severity: Severity;
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED';
  source: string;
  summary?: string;
  riskScore?: number;
  priority?: 'P1' | 'P2' | 'P3' | 'P4';
}

export interface Agent {
  id: number;
  agent_id: string;
  hostname: string;
  ip_address: string;
  os: string;
  last_seen: string;
  created_at: string;
}

export interface Telemetry {
  id: number;
  agent_id: string;
  timestamp: string;
  cpu_percent: number;
  ram_percent: number;
  disk_percent: number;
  process_count: number;
  connection_count: number;
  raw_json?: any;
}

export interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  source: string;
}

export interface AnalysisResult {
  riskScore: number;
  threatDetected: boolean;
  explanation: string;
  recommendations: string[];
  threatVectors?: {
    persistence: number;
    lateralMovement: number;
    exfiltration: number;
    reconnaissance: number;
    credentialAccess: number;
  };
}

export interface AlertAnalysisResponse {
  riskScore: number;
  explanation: string;
  recommendedActions: string[];
  mitreMapping: string[];
}

export interface BriefingResult {
  brief: string;
  vectors: {
    persistence: number;
    lateralMovement: number;
    exfiltration: number;
    reconnaissance: number;
    credentialAccess: number;
  };
}

export interface CorrelationResult {
  summary: string;
  relationshipScore: number;
  keyInsights: string[];
}

export interface GroundingSource {
  title: string;
  uri: string;
}

export interface PlaybookStep {
  title: string;
  action: string;
  query?: string;
}

export interface Playbook {
  name: string;
  objective: string;
  steps: PlaybookStep[];
}
