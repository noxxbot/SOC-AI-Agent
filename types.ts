
export enum Severity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface Incident {
  id: number | string;
  created_at?: string;
  updated_at?: string;
  title?: string;
  summary?: string;
  severity?: Severity | string;
  confidence_score?: number;
  incident_fingerprint?: string;
  source?: string;
  agent_id?: string;
  hostname?: string;
  primary_iocs?: any[];
  mitre_techniques?: any[];
  related_alert_ids?: number[];
  related_log_fingerprints?: string[];
  decision_reason?: string;
  agentId?: string;
  timestamp?: string;
  status?: 'OPEN' | 'INVESTIGATING' | 'RESOLVED';
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

export interface ProcessedLog {
  id: number;
  agent_id: string;
  hostname: string;
  timestamp: string | null;
  category: string;
  event_type: string;
  severity_score: number;
  message: string;
  raw: string;
  fields_json: Record<string, any>;
  iocs_json: {
    ips?: string[];
    domains?: string[];
    sha256?: string[];
    md5?: string[];
    cves?: string[];
  };
  tags_json: string[];
  fingerprint?: string | null;
  created_at?: string | null;
  mitre_matches?: any[];
  ioc_intel?: Record<string, any>;
  ai_notes?: Record<string, any> | null;
}

export interface Alert {
  id: number;
  created_at?: string | null;
  alert_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  confidence_score: number;
  category: string;
  status: string;
  summary?: string | null;
  evidence: Record<string, any>;
  mitre: any[];
  ioc_matches: any[];
  recommended_actions: string[];
  fingerprint?: string | null;
  investigated?: boolean;
}

export interface Investigation {
  id: number;
  created_at?: string | null;
  alert_id: number;
  model_name?: string | null;
  prompt_hash?: string | null;
  investigation: Record<string, any>;
  confidence_score: number;
  is_incident: boolean;
  incident_severity: string;
  status: string;
  error_message?: string | null;
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
