
import React, { useState, useEffect, useMemo } from 'react';
import { Incident, Severity, Playbook, AnalysisResult, Telemetry, CorrelationResult, Alert, Investigation } from '../types';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip } from 'recharts';
import { api } from '../services/api';

interface IncidentDetailProps {
  incident: Incident;
  onBack: () => void;
}

const normalizeTechniqueId = (value: any) => {
  const text = String(value || '').trim();
  const match = text.match(/(T\d{4}(?:\.\d{3})?)/i);
  return match ? match[1].toUpperCase() : text.toUpperCase();
};

const uniqueStrings = (items: string[]) => {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = item.trim();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};


const coerceIncidentId = (incident: Incident) => {
  const raw = incident.id;
  const numeric = typeof raw === 'number' ? raw : Number(String(raw).replace(/\D/g, ''));
  return Number.isFinite(numeric) ? numeric : null;
};

const splitParagraphs = (text: string) => {
  return String(text || '')
    .split(/\n+/)
    .map((t) => t.trim())
    .filter(Boolean);
};

const formatIncidentTimestamp = (incident: Incident) => {
  const raw = incident.timestamp || incident.created_at || incident.updated_at;
  if (!raw) return 'Not available';
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return String(raw);
  return date.toLocaleString();
};


const mergeEvidence = (base: string[], extra: string[]) => {
  return uniqueStrings([...(base || []), ...(extra || [])].map((item) => String(item || '').trim()).filter(Boolean));
};

const normalizeActions = (actions: string[], aiConfidence: number, fallback: string[]) => {
  const cleaned = uniqueStrings((actions || []).map((item) => String(item || '').trim()).filter(Boolean));
  const filtered = aiConfidence >= 80
    ? cleaned
    : cleaned.filter((item) => !/(contain|isolate|block|quarantine)/i.test(item));
  const combined = filtered.length ? filtered : (fallback || []);
  return uniqueStrings(combined).slice(0, 3);
};

const collectMitreMatches = (incident: Incident, detections: Alert[]) => {
  const fromAlerts = detections.flatMap((alert) => Array.isArray(alert.mitre) ? alert.mitre : []);
  const fromIncident = (incident.mitre_techniques || []) as any[];
  return [...fromAlerts, ...fromIncident].filter(Boolean);
};

const collectIocMatches = (incident: Incident, detections: Alert[]) => {
  const fromAlerts = detections.flatMap((alert) => Array.isArray(alert.ioc_matches) ? alert.ioc_matches : []);
  const fromIncident = (incident.primary_iocs || []) as any[];
  return [...fromAlerts, ...fromIncident].filter(Boolean);
};

const extractTactics = (mitreMatches: any[]) => {
  const tactics = mitreMatches.flatMap((m) => (m?.tactics || m?.tactic || []));
  return uniqueStrings(tactics.map((t: any) => String(t || '').toLowerCase().replace(/[\s-]+/g, '_')));
};

const extractTechniqueIds = (mitreMatches: any[]) => {
  return uniqueStrings(
    mitreMatches
      .map((m) => normalizeTechniqueId(m?.technique_id || m?.id || m?.technique))
      .filter(Boolean)
  );
};

const deriveTacticalBriefing = (
  incident: Incident,
  detections: Alert[],
  investigation: Investigation | null
) => {
  const severity = String(incident.severity || 'unknown').toLowerCase();
  const decisionReason = String((incident as any).decision_reason || '').trim();
  const aiConfidence = Number(investigation?.confidence_score || 0);

  const mitreMatches = collectMitreMatches(incident, detections);
  const tactics = extractTactics(mitreMatches);
  const techniques = extractTechniqueIds(mitreMatches);

  const ruleNames = uniqueStrings(
    detections.map((d) => d.rule_name).filter(Boolean) as string[]
  );

  const iocMatches = collectIocMatches(incident, detections);
  const iocVerdicts = uniqueStrings(
    iocMatches
      .map((ioc) => {
        const verdict = String(ioc?.verdict || ioc?.risk || '').toLowerCase();
        const value = String(ioc?.ioc || ioc?.indicator || '').trim();
        const confidence = ioc?.confidence ?? ioc?.confidence_score;
        const confidenceText = typeof confidence === 'number' ? ` (${confidence}%)` : '';
        if (!verdict && !value) return '';
        return verdict ? `${verdict.toUpperCase()}: ${value || 'IOC'}${confidenceText}` : value;
      })
      .filter(Boolean)
  );

  const correlationReasons = uniqueStrings(
    detections
      .flatMap((d) => (d.evidence as any)?.correlation_reasons || [])
      .map((r: any) => String(r || '').trim())
      .filter(Boolean)
  );

  // Deterministic Incident Focus sentence.
  const tacticLabel = tactics.length
    ? tactics.slice(0, 2).map((t) => t.replace(/_/g, ' ')).join(' and ')
    : 'multi-stage';
  const ruleLabel = ruleNames.length ? ruleNames.slice(0, 2).join(' + ') : 'linked detections';
  const focus = `${severity.toUpperCase()} incident involving ${tacticLabel} activity detected by ${ruleLabel}.`;

  // Why This Is an Incident (deterministic bullets).
  const why: string[] = [];
  if (decisionReason) why.push(`Policy decision: ${decisionReason}`);
  if (severity === 'critical' || severity === 'high') why.push(`Severity rated as ${severity.toUpperCase()} for escalation.`);
  if (correlationReasons.length) why.push('Correlation signals indicate multi-step activity.');
  if (tactics.includes('credential_access')) why.push('Credential access tactics observed in detections.');
  if (iocVerdicts.some((v) => v.startsWith('MALICIOUS') || v.startsWith('SUSPICIOUS'))) {
    why.push('IOC intelligence includes malicious or suspicious verdicts.');
  }
  if (investigation?.status === 'completed') {
    why.push('AI investigation completed for this incident.');
  }
  if (!why.length) why.push('Multiple detection signals met incident policy thresholds.');

  // Evidence Considered
  const evidence: string[] = [];
  if (ruleNames.length) evidence.push(`Detection rules: ${ruleNames.join(', ')}`);
  if (techniques.length) evidence.push(`MITRE techniques: ${techniques.join(', ')}`);
  if (iocVerdicts.length) evidence.push(`IOC verdicts: ${iocVerdicts.join(', ')}`);
  if (correlationReasons.length) evidence.push(`Correlation findings: ${correlationReasons.join(', ')}`);
  if (!evidence.length) evidence.push('No additional structured evidence available.');

  // Analyst Next Actions (deterministic based on tactics + severity)
  const actions: string[] = [];
  const addAction = (text: string) => {
    if (!actions.includes(text)) actions.push(text);
  };
  addAction('Validate affected host timelines and recent activity.');
  if (tactics.includes('credential_access')) addAction('Review credential usage and authentication events.');
  if (tactics.includes('execution')) addAction('Inspect process lineage and command execution artifacts.');
  if (tactics.includes('lateral_movement')) addAction('Check lateral movement indicators across hosts.');
  if (tactics.includes('command_and_control')) addAction('Review outbound connections for C2 patterns.');
  if (tactics.includes('persistence')) addAction('Hunt for persistence mechanisms on the host.');
  if (aiConfidence >= 80) addAction('Contain the host if malicious activity is confirmed.');
  if (actions.length < 3) addAction('Review related alerts and logs for supporting evidence.');
  const boundedActions = actions.slice(0, 3);

  // Threat Vector Profile (0-5 scale)
  const techniqueSet = new Set(techniques);
  const tacticSet = new Set(tactics);
  const hasCorrelation = correlationReasons.length > 0;

  const scoreAxis = (tacticKey: string, strongTechs: string[], weakKeywords: string[], label: string) => {
    let score = 0;
    let rationale = 'No evidence observed for this dimension.';

    if (tacticSet.has(tacticKey)) {
      score = 4;
      rationale = `Observed tactic: ${label}.`;
    }

    const strong = strongTechs.find((t) => techniqueSet.has(t));
    if (strong) {
      score = 5;
      rationale = `Observed technique: ${strong}.`;
    }

    if (!score && hasCorrelation) {
      const hit = correlationReasons.find((r) => weakKeywords.some((k) => r.toLowerCase().includes(k)));
      if (hit) {
        score = 3;
        rationale = `Correlation signal: ${hit}.`;
      }
    }

    if ((severity === 'critical' || severity === 'high') && score > 0) {
      const boosted = Math.max(score, 4);
      if (boosted !== score) {
        score = boosted;
        rationale = `${rationale} Severity escalated confidence.`;
      }
    }

    return { score, rationale };
  };

  const initialAccess = scoreAxis('initial_access', ['T1566', 'T1190'], ['initial access', 'phishing'], 'Initial Access');
  const execution = scoreAxis('execution', ['T1059', 'T1059.001', 'T1055'], ['execution', 'command'], 'Execution');
  const persistence = scoreAxis('persistence', ['T1053', 'T1547'], ['persistence'], 'Persistence');
  const credentialAccess = scoreAxis('credential_access', ['T1003', 'T1003.001', 'T1110'], ['credential'], 'Credential Access');
  const lateralMovement = scoreAxis('lateral_movement', ['T1021', 'T1077'], ['lateral'], 'Lateral Movement');
  const commandControl = scoreAxis('command_and_control', ['T1071', 'T1105'], ['command and control', 'c2'], 'Command & Control');
  const exfiltration = scoreAxis('exfiltration', ['T1041', 'T1567'], ['exfiltration'], 'Exfiltration');

  const vectorScores = [
    { subject: 'Initial Access', A: initialAccess.score, rationale: initialAccess.rationale },
    { subject: 'Execution', A: execution.score, rationale: execution.rationale },
    { subject: 'Persistence', A: persistence.score, rationale: persistence.rationale },
    { subject: 'Credential Access', A: credentialAccess.score, rationale: credentialAccess.rationale },
    { subject: 'Lateral Movement', A: lateralMovement.score, rationale: lateralMovement.rationale },
    { subject: 'Command & Control', A: commandControl.score, rationale: commandControl.rationale },
    { subject: 'Exfiltration', A: exfiltration.score, rationale: exfiltration.rationale }
  ];

  return { focus, why, evidence, actions: boundedActions, vectorScores, aiConfidence };

};

const buildPlaybooks = (analysis: AnalysisResult, incident: Incident): Playbook[] => {
  if (!analysis.recommendations || analysis.recommendations.length === 0) return [];
  const steps = analysis.recommendations.slice(0, 6).map((rec, idx) => ({
    title: `Step ${idx + 1}`,
    action: rec
  }));

  return [
    {
      name: incident.title ? `${incident.title} Response` : 'Incident Response Playbook',
      objective: incident.summary || 'Contain and remediate the incident.',
      steps
    }
  ];
};

const buildCorrelationResult = (incident: Incident, relatedAlerts: Incident[], telemetry: Telemetry[]): CorrelationResult => {
  const alertCount = relatedAlerts.length;
  const telemetryCount = telemetry.length;
  const avgCpu = telemetryCount ? telemetry.reduce((sum, item) => sum + item.cpu_percent, 0) / telemetryCount : 0;
  const avgRam = telemetryCount ? telemetry.reduce((sum, item) => sum + item.ram_percent, 0) / telemetryCount : 0;
  const signalScore = Math.min(100, 35 + alertCount * 12 + Math.round((avgCpu + avgRam) / 4));

  const insights = [];
  if (alertCount > 0) insights.push(`${alertCount} related alerts observed for the same agent.`);
  if (telemetryCount > 0) insights.push(`Telemetry shows average CPU ${Math.round(avgCpu)}% and RAM ${Math.round(avgRam)}%.`);
  if (incident.summary) insights.push(`Incident summary indicates: ${incident.summary}`);
  if (relatedAlerts[0]?.title) insights.push(`Most recent related alert: ${relatedAlerts[0].title}.`);

  return {
    summary: `Correlation synthesized from ${alertCount} related alerts and ${telemetryCount} telemetry records.`,
    relationshipScore: signalScore,
    keyInsights: insights.length ? insights : ['No additional context available for correlation.']
  };
};

const IncidentDetail: React.FC<IncidentDetailProps> = ({ incident, onBack }) => {
  const [activeSubTab, setActiveSubTab] = useState<'overview' | 'holistic' | 'logs'>('overview');
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [loadingPlaybooks, setLoadingPlaybooks] = useState(false);
  const [relatedDetections, setRelatedDetections] = useState<Alert[]>([]);
  const [briefingInvestigation, setBriefingInvestigation] = useState<Investigation | null>(null);
  const [loadingBrief, setLoadingBrief] = useState(false);
  const [llmBriefing, setLlmBriefing] = useState<{ focus: string; actions: string[]; data_gaps: string[] } | null>(null);
  const [loadingLlmBriefing, setLoadingLlmBriefing] = useState(false);

  // Correlation States
  const [relatedAlerts, setRelatedAlerts] = useState<Incident[]>([]);
  const [relatedTelemetry, setRelatedTelemetry] = useState<Telemetry[]>([]);
  const [correlationResult, setCorrelationResult] = useState<CorrelationResult | null>(null);
  const [loadingCorrelation, setLoadingCorrelation] = useState(false);

  // Evidence Logs State
  const [evidenceLogs, setEvidenceLogs] = useState('');
  const [analyzingLogs, setAnalyzingLogs] = useState(false);
  const [logAnalysisResult, setLogAnalysisResult] = useState<AnalysisResult | null>(null);
  const [completedLogTasks, setCompletedLogTasks] = useState<number[]>([]);

  useEffect(() => {
    const fetchBriefingData = async () => {
      const ids = Array.isArray(incident.related_alert_ids) ? incident.related_alert_ids : [];
      if (!ids.length) {
        setRelatedDetections([]);
        setBriefingInvestigation(null);
        setLoadingBrief(false);
        return;
      }
      setLoadingBrief(true);
      try {
        const detections = await Promise.all(ids.map((id) => api.getDetectionAlert(Number(id))));
        setRelatedDetections(detections.filter(Boolean));

        // Pull latest completed investigation (if any) for briefing context.
        const investigations = await Promise.all(ids.map((id) => api.getInvestigations(Number(id))));
        const flat = investigations.flat().filter(Boolean) as Investigation[];
        const completed = flat.filter((inv) => String(inv.status || '').toLowerCase() === 'completed');
        const pool = completed.length ? completed : flat;
        const best = pool.sort((a, b) => (b.confidence_score || 0) - (a.confidence_score || 0))[0] || null;
        setBriefingInvestigation(best || null);
      } catch (e) {
        console.error('Briefing data load failed', e);
        setRelatedDetections([]);
        setBriefingInvestigation(null);
      } finally {
        setLoadingBrief(false);
      }
    };
    fetchBriefingData();
  }, [incident.related_alert_ids]);


  useEffect(() => {
    const incidentId = coerceIncidentId(incident);
    if (!incidentId) {
      setLlmBriefing(null);
      return;
    }

    let isActive = true;
    const fetchLlmBriefing = async () => {
      setLoadingLlmBriefing(true);
      try {
        const data = await api.getIncidentTacticalBriefing(incidentId);
        if (!isActive) return;
        setLlmBriefing(data || null);
      } catch (e) {
        console.error('Tactical AI briefing enrichment failed', e);
        if (isActive) setLlmBriefing(null);
      } finally {
        if (isActive) setLoadingLlmBriefing(false);
      }
    };

    fetchLlmBriefing();
    return () => { isActive = false; };
  }, [incident.id]);

  // Handle data fetching for holistic view
  useEffect(() => {
    if (activeSubTab === 'holistic' && !correlationResult) {
      handleFetchCorrelation();
    }
  }, [activeSubTab]);

  const handleFetchCorrelation = async () => {
    setLoadingCorrelation(true);
    try {
      const agentId = incident.agentId || incident.agent_id;
      const [allAlerts, telemetry] = await Promise.all([
        api.getAlerts(),
        agentId ? api.getTelemetry(agentId, 30) : Promise.resolve([])
      ]);

      // Filter alerts for same agent, excluding the current one
      const agentAlerts = agentId ? allAlerts.filter(a => a.agentId === agentId && a.id !== incident.id) : [];
      setRelatedAlerts(agentAlerts);
      setRelatedTelemetry(telemetry);

      setCorrelationResult(buildCorrelationResult(incident, agentAlerts, telemetry));
    } catch (error) {
      console.error("Correlation fetch error:", error);
    } finally {
      setLoadingCorrelation(false);
    }
  };

  const getSeverityStyles = (severity: Severity) => {
    switch (severity) {
      case Severity.CRITICAL: return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
      case Severity.HIGH: return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case Severity.MEDIUM: return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      case Severity.LOW: return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
      default: return 'text-slate-500 bg-slate-500/10 border-slate-500/20';
    }
  };

  const handleGeneratePlaybooks = async () => {
    setLoadingPlaybooks(true);
    try {
      const prompt = [incident.title, incident.summary, incident.source, incident.agentId, incident.agent_id]
        .filter(Boolean)
        .join('\n');
      const analysis = await api.analyzeLogs(prompt || 'Incident playbook generation request');
      setPlaybooks(buildPlaybooks(analysis, incident));
    } catch (error) {
      console.error(error);
      alert('Failed to generate playbooks.');
    } finally {
      setLoadingPlaybooks(false);
    }
  };

  const handleAnalyzeLogs = async () => {
    if (!evidenceLogs.trim()) return;
    setAnalyzingLogs(true);
    setCompletedLogTasks([]);
    try {
      const result = await api.analyzeLogs(evidenceLogs);
      setLogAnalysisResult(result);
    } catch (error) {
      console.error(error);
      alert('Failed to analyze logs.');
    } finally {
      setAnalyzingLogs(false);
    }
  };

  const toggleLogTask = (index: number) => {
    setCompletedLogTasks(prev => 
      prev.includes(index) ? prev.filter(i => i !== index) : [...prev, index]
    );
  };

  // Deterministic briefing derived from incident + detections + investigations (no AI calls).
  const tacticalBriefing = useMemo(
    () => deriveTacticalBriefing(incident, relatedDetections, briefingInvestigation),
    [incident, relatedDetections, briefingInvestigation]
  );

  const focusParagraphs = splitParagraphs(llmBriefing?.focus || tacticalBriefing.focus);
  const mergedEvidence = mergeEvidence(tacticalBriefing.evidence, llmBriefing?.data_gaps || []);
  const mergedActions = normalizeActions(llmBriefing?.actions || [], tacticalBriefing.aiConfidence || 0, tacticalBriefing.actions);
  const briefingLoading = loadingBrief || loadingLlmBriefing;

  const logThreatData = logAnalysisResult?.threatVectors ? [
    { subject: 'Persistence', A: logAnalysisResult.threatVectors.persistence, fullMark: 100 },
    { subject: 'Lateral Movement', A: logAnalysisResult.threatVectors.lateralMovement, fullMark: 100 },
    { subject: 'Exfiltration', A: logAnalysisResult.threatVectors.exfiltration, fullMark: 100 },
    { subject: 'Reconnaissance', A: logAnalysisResult.threatVectors.reconnaissance, fullMark: 100 },
    { subject: 'Cred Access', A: logAnalysisResult.threatVectors.credentialAccess, fullMark: 100 },
  ] : [];

  const logCompletionRate = logAnalysisResult && logAnalysisResult.recommendations.length
    ? Math.round((completedLogTasks.length / logAnalysisResult.recommendations.length) * 100)
    : 0;

  const renderVectorTooltip = ({ active, payload }: any) => {
    if (!active || !payload || !payload.length) return null;
    const item = payload[0]?.payload;
    if (!item) return null;
    return (
      <div className="bg-slate-950 border border-slate-700 rounded-lg p-3 shadow-xl max-w-xs">
        <div className="text-xs font-bold text-emerald-400">{item.subject}</div>
        <div className="text-[10px] text-slate-400 mt-1">Score: {item.A}/5</div>
        <div className="text-[10px] text-slate-300 mt-2">{item.rationale}</div>
      </div>
    );
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-in fade-in slide-in-from-right-4 duration-300 pb-20">
      <header className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <button 
            onClick={onBack}
            className="w-10 h-10 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400 hover:text-white hover:border-slate-700 transition-all shadow-lg"
          >
            <i className="fa-solid fa-arrow-left"></i>
          </button>
          <div>
            <div className="flex items-center gap-3 mb-1">
              <span className="font-mono text-xs font-bold text-emerald-500 bg-emerald-500/5 px-2 py-0.5 rounded border border-emerald-500/10">
                {incident.id}
              </span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-tighter ${getSeverityStyles(incident.severity)}`}>
                {incident.severity}
              </span>
            </div>
            <h1 className="text-2xl font-bold text-slate-50">{incident.title}</h1>
          </div>
        </div>
        <div className="flex gap-2">
          <button className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded-lg text-sm font-medium transition-all border border-slate-700">
            Assign to Me
          </button>
          <button className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all shadow-lg">
            Resolve Case
          </button>
        </div>
      </header>

      {/* Internal Tabs */}
      <div className="flex gap-1 bg-slate-900/50 p-1 rounded-xl border border-slate-800 w-fit shadow-lg">
        <button 
          onClick={() => setActiveSubTab('overview')}
          className={`px-4 py-2 rounded-lg text-sm font-bold transition-all flex items-center gap-2 ${activeSubTab === 'overview' ? 'bg-slate-800 text-emerald-400 shadow-inner' : 'text-slate-500 hover:text-slate-300'}`}
        >
          <i className="fa-solid fa-eye text-xs"></i> Overview
        </button>
        <button 
          onClick={() => setActiveSubTab('holistic')}
          className={`px-4 py-2 rounded-lg text-sm font-bold transition-all flex items-center gap-2 ${activeSubTab === 'holistic' ? 'bg-slate-800 text-emerald-400 shadow-inner' : 'text-slate-500 hover:text-slate-300'}`}
        >
          <i className="fa-solid fa-diagram-project text-xs"></i> Holistic View
        </button>
        <button 
          onClick={() => setActiveSubTab('logs')}
          className={`px-4 py-2 rounded-lg text-sm font-bold transition-all flex items-center gap-2 ${activeSubTab === 'logs' ? 'bg-slate-800 text-emerald-400 shadow-inner' : 'text-slate-500 hover:text-slate-300'}`}
        >
          <i className="fa-solid fa-file-lines text-xs"></i> Evidence Logs
        </button>
      </div>

      
{activeSubTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
              <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Incident Summary</h3>
              <p className="text-slate-300 leading-relaxed text-lg">
                {incident.summary || "No detailed summary available for this incident."}
              </p>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl border-l-4 border-l-emerald-500">
              <div className="p-4 bg-slate-800/30 border-b border-slate-800 flex justify-between items-center">
                <h3 className="text-sm font-bold text-emerald-400 uppercase tracking-widest flex items-center gap-2">
                  <i className="fa-solid fa-bolt-lightning"></i>
                  Tactical AI Briefing
                </h3>
                {briefingLoading && <i className="fa-solid fa-circle-notch fa-spin text-emerald-500 text-xs"></i>}
              </div>
              <div className="p-6">
                {briefingLoading ? (
                  <div className="animate-pulse space-y-2">
                    <div className="h-4 bg-slate-800 rounded w-3/4"></div>
                    <div className="h-4 bg-slate-800 rounded w-1/2"></div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="bg-slate-950/40 border border-slate-800 rounded-xl p-5 shadow-inner">
                      <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Incident Focus</div>
                      <div className="space-y-3">
                        {(focusParagraphs.length ? focusParagraphs : ['No incident focus available.']).map((paragraph, idx) => (
                          <p key={`focus-${idx}`} className="text-sm text-slate-200 leading-relaxed">
                            {paragraph}
                          </p>
                        ))}
                      </div>
                    </div>

                    <div className="bg-slate-950/40 border border-slate-800 rounded-xl p-5 shadow-inner">
                      <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Why This Is an Incident</div>
                      <ul className="space-y-2 text-sm text-slate-200">
                        {(tacticalBriefing.why.length ? tacticalBriefing.why : ['No policy escalation signals available.']).map((item, idx) => (
                          <li key={`why-${idx}`} className="flex gap-2">
                            <span className="text-emerald-400">-</span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div className="bg-slate-950/40 border border-slate-800 rounded-xl p-5 shadow-inner">
                      <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Evidence Considered</div>
                      <ul className="space-y-2 text-sm text-slate-200">
                        {(mergedEvidence.length ? mergedEvidence : ['No structured evidence available.']).map((item, idx) => (
                          <li key={`evidence-${idx}`} className="flex gap-2">
                            <span className="text-emerald-400">-</span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div className="bg-slate-950/40 border border-slate-800 rounded-xl p-5 shadow-inner">
                      <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Analyst Next Actions</div>
                      <ul className="space-y-2 text-sm text-slate-200">
                        {(mergedActions.length ? mergedActions : ['Review alert evidence and validate scope.']).map((item, idx) => (
                          <li key={`action-${idx}`} className="flex gap-2">
                            <span className="text-emerald-400">-</span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
              <div className="p-4 bg-slate-800/50 border-b border-slate-800 flex justify-between items-center">
                <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                  <i className="fa-solid fa-wand-magic-sparkles text-emerald-400"></i>
                  Tactical Threat Hunting Playbooks
                </h3>
                {!playbooks.length && !loadingPlaybooks && (
                  <button 
                    onClick={handleGeneratePlaybooks}
                    className="text-xs bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1 rounded font-bold transition-all flex items-center gap-2"
                  >
                    <i className="fa-solid fa-sparkles"></i>
                    Generate Procedures
                  </button>
                )}
              </div>
              <div className="p-6">
                {loadingPlaybooks ? (
                  <div className="flex flex-col items-center justify-center py-12 text-slate-500">
                    <i className="fa-solid fa-dna fa-spin text-3xl mb-4 text-emerald-500"></i>
                    <p className="text-sm animate-pulse">Kavach AI is drafting hunting procedures...</p>
                  </div>
                ) : playbooks.length > 0 ? (
                  <div className="space-y-6">
                    {playbooks.map((pb, i) => (
                      <div key={i} className="bg-slate-950 border border-slate-800 rounded-xl p-6 flex flex-col group hover:border-emerald-500/30 transition-all shadow-lg">
                        <h4 className="font-bold text-lg text-emerald-400 group-hover:text-emerald-300 transition-colors">{pb.name}</h4>
                        <p className="text-xs text-slate-500 italic mt-1">{pb.objective}</p>
                        <div className="space-y-4 mt-4">
                          {pb.steps.map((step, si) => (
                            <div key={si} className="bg-slate-900/40 p-4 rounded-xl border border-slate-800/50">
                              <p className="text-sm font-semibold text-slate-200">{step.title}</p>
                              <p className="text-xs text-slate-400 leading-relaxed mt-1">{step.action}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-12 text-slate-600 border-2 border-dashed border-slate-800 rounded-xl">
                    <i className="fa-solid fa-shield-virus text-4xl mb-4 opacity-10"></i>
                    <p className="text-sm">No tactical playbooks generated yet.</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="grid grid-cols-1 gap-6 p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl">
              <div>
                <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Source Origin</h4>
                <div className="flex items-center gap-2 text-slate-200 text-sm">
                  <i className="fa-solid fa-satellite text-emerald-500"></i>
                  {incident.source}
                </div>
              </div>
              <div>
                <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Detected At</h4>
                <div className="flex items-center gap-2 text-slate-200 text-sm">
                  <i className="fa-solid fa-clock text-slate-400"></i>
                  {formatIncidentTimestamp(incident)}
                </div>
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Threat Vector Profile</h3>
                <span className="text-[10px] text-slate-600">Scale: 0-5</span>
              </div>
              <div className="text-[10px] text-slate-500 mb-4">Derived from observed techniques and correlations (deterministic).</div>
              <div className="h-56 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart cx="50%" cy="50%" outerRadius="75%" data={tacticalBriefing.vectorScores}>
                    <defs>
                      <linearGradient id="tvpFill" x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0%" stopColor="#10b981" stopOpacity="0.65" />
                        <stop offset="100%" stopColor="#22c55e" stopOpacity="0.3" />
                      </linearGradient>
                    </defs>
                    <PolarGrid stroke="#1f2937" radialLines={true} />
                    <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 9 }} />
                    <PolarRadiusAxis angle={30} domain={[0, 5]} tick={{ fill: '#64748b', fontSize: 8 }} axisLine={false} />
                    <Tooltip content={renderVectorTooltip} />
                    <Radar
                      name="Threat Vector"
                      dataKey="A"
                      stroke="#10b981"
                      strokeWidth={2}
                      fill="url(#tvpFill)"
                      fillOpacity={0.6}
                      dot={{ r: 3, fill: '#10b981' }}
                      activeDot={{ r: 5 }}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-4 space-y-2">
                {tacticalBriefing.vectorScores.map((item) => (
                  <div key={item.subject} className="bg-slate-950/40 border border-slate-800 rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] text-slate-200">{item.subject}</span>
                      <span className="text-[10px] font-mono text-emerald-400">{item.A}/5</span>
                    </div>
                    <div className="mt-2 h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                      <div className="h-full bg-emerald-500" style={{ width: `${item.A * 20}%` }}></div>
                    </div>
                    <div className="text-[10px] text-slate-500 mt-2">{item.rationale}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

{activeSubTab === 'holistic' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="lg:col-span-2 space-y-6">
            {/* Timeline correlation card */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
              <div className="p-4 bg-slate-800/50 border-b border-slate-800 flex justify-between items-center">
                <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                   <i className="fa-solid fa-timeline text-emerald-500"></i>
                   Agent Activity Timeline
                </h3>
                <span className="text-[10px] font-mono text-slate-500">±1H CONTEXT WINDOW</span>
              </div>
              
              <div className="p-8 relative">
                {/* Vertical line for timeline */}
                <div className="absolute left-10 top-8 bottom-8 w-0.5 bg-slate-800"></div>
                
                <div className="space-y-12">
                  {/* Primary Incident Node */}
                  <div className="relative pl-12">
                    <div className="absolute left-[3px] top-1 w-5 h-5 rounded-full bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.5)] border-4 border-slate-900 z-10"></div>
                    <div>
                      <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-widest mb-1 block">Primary Event</span>
                      <h4 className="text-lg font-bold text-white">{incident.title}</h4>
                      <p className="text-xs text-slate-400 mt-1">{formatIncidentTimestamp(incident)}</p>
                      <div className="mt-3 p-3 bg-emerald-500/5 border border-emerald-500/10 rounded-xl text-sm text-slate-300">
                        Initial detection point for this investigation.
                      </div>
                    </div>
                  </div>

                  {/* Related Alerts */}
                  {relatedAlerts.map((alt, idx) => (
                    <div key={idx} className="relative pl-12">
                      <div className="absolute left-[3px] top-1 w-5 h-5 rounded-full bg-amber-500 border-4 border-slate-900 z-10"></div>
                      <div>
                        <span className="text-[10px] font-bold text-amber-500 uppercase tracking-widest mb-1 block">Related Alert</span>
                        <h4 className="text-md font-bold text-slate-200">{alt.title}</h4>
                        <p className="text-xs text-slate-400 mt-1">{alt.timestamp}</p>
                        <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded border mt-2 inline-block ${getSeverityStyles(alt.severity)}`}>
                          {alt.severity}
                        </span>
                      </div>
                    </div>
                  ))}

                  {/* Telemetry Events (Simulated/Derived) */}
                  {relatedTelemetry.slice(0, 3).map((tel, idx) => (
                    <div key={`tel-${idx}`} className="relative pl-12">
                      <div className="absolute left-[3.5px] top-1 w-4 h-4 rounded-full bg-blue-500/30 border-2 border-slate-800 z-10"></div>
                      <div>
                        <span className="text-[10px] font-bold text-blue-500 uppercase tracking-widest mb-1 block">Telemetry Data Point</span>
                        <div className="flex gap-4">
                           <div className="bg-slate-950 p-2 rounded-lg border border-slate-800 text-center flex-1">
                             <p className="text-[9px] text-slate-500 mb-0.5">CPU</p>
                             <p className="text-xs font-bold text-emerald-400">{Math.round(tel.cpu_percent)}%</p>
                           </div>
                           <div className="bg-slate-950 p-2 rounded-lg border border-slate-800 text-center flex-1">
                             <p className="text-[9px] text-slate-500 mb-0.5">RAM</p>
                             <p className="text-xs font-bold text-blue-400">{Math.round(tel.ram_percent)}%</p>
                           </div>
                           <div className="bg-slate-950 p-2 rounded-lg border border-slate-800 text-center flex-1">
                             <p className="text-[9px] text-slate-500 mb-0.5">NET_CONNS</p>
                             <p className="text-xs font-bold text-slate-200">{tel.connection_count}</p>
                           </div>
                        </div>
                        <p className="text-[9px] text-slate-600 mt-2 font-mono uppercase">{new Date(tel.timestamp).toLocaleTimeString()}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl relative overflow-hidden group">
              {/* Background Glow */}
              <div className="absolute -top-24 -right-24 w-48 h-48 bg-emerald-500/10 blur-[100px] rounded-full pointer-events-none group-hover:bg-emerald-500/20 transition-all duration-1000"></div>
              
              <h3 className="text-sm font-bold text-emerald-400 uppercase tracking-widest mb-6 flex items-center gap-2">
                 <i className="fa-solid fa-brain"></i>
                 AI Correlation Synthesis
              </h3>

              {loadingCorrelation ? (
                <div className="flex flex-col items-center py-12 text-slate-500 gap-4">
                  <i className="fa-solid fa-circle-nodes fa-spin text-3xl text-emerald-500"></i>
                  <p className="text-xs animate-pulse font-mono uppercase tracking-widest">Bridging Data Silos...</p>
                </div>
              ) : correlationResult ? (
                <div className="space-y-6 animate-in fade-in duration-500">
                  <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 relative z-10">
                    <p className="text-sm text-slate-300 leading-relaxed italic">
                      "{correlationResult.summary}"
                    </p>
                  </div>

                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl">
                    <div className="flex justify-between items-center mb-4">
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Correlation Confidence</span>
                      <span className="text-sm font-mono font-bold text-emerald-500">{correlationResult.relationshipScore}%</span>
                    </div>
                    <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                      <div 
                        className="h-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)] transition-all duration-1000" 
                        style={{ width: `${correlationResult.relationshipScore}%` }}
                      ></div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Key Cross-Context Insights</h4>
                    <div className="space-y-3">
                      {correlationResult.keyInsights.map((insight, idx) => (
                        <div key={idx} className="flex gap-3 text-xs text-slate-400 leading-relaxed p-2 hover:bg-slate-800/30 rounded-lg transition-all">
                           <i className="fa-solid fa-arrow-right text-emerald-500 mt-1"></i>
                           <span>{insight}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <button 
                    onClick={handleFetchCorrelation}
                    className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-400 text-[10px] font-bold uppercase rounded-lg border border-slate-700 transition-all"
                  >
                    Re-run Contextualization
                  </button>
                </div>
              ) : (
                <div className="text-center py-12">
                   <p className="text-slate-600 text-sm">Context correlation failed to initialize.</p>
                </div>
              )}
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
               <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Affected Assets</h3>
               <div className="flex items-center gap-4 bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <div className="w-10 h-10 bg-emerald-500/10 rounded-lg flex items-center justify-center text-emerald-500">
                    <i className="fa-solid fa-server"></i>
                  </div>
                  <div>
                    <p className="text-sm font-bold text-slate-200">{incident.agentId}</p>
                    <p className="text-[10px] text-slate-500 uppercase">Tier 1 Critical Asset</p>
                  </div>
               </div>
            </div>
          </div>
        </div>
      )}

      {activeSubTab === 'logs' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in slide-in-from-bottom-4 fade-in duration-300">
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
              <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Evidence Log Submission</h3>
              <p className="text-xs text-slate-500 mb-4">Paste raw forensics data for AI-augmented threat correlation.</p>
              <textarea 
                value={evidenceLogs}
                onChange={(e) => setEvidenceLogs(e.target.value)}
                className="w-full h-80 bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-sm text-slate-300 focus:border-emerald-500 outline-none transition-all resize-none shadow-inner"
                placeholder="2024-05-20T14:42:10Z SRC=185.220.101.44 DST=10.0.1.5 PROTO=TCP DPT=22..."
              />
              <button 
                onClick={handleAnalyzeLogs}
                disabled={analyzingLogs || !evidenceLogs.trim()}
                className="mt-4 w-full bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-600 text-white py-3 rounded-xl font-bold transition-all flex items-center justify-center gap-2 shadow-lg"
              >
                {analyzingLogs ? <i className="fa-solid fa-circle-notch fa-spin"></i> : <i className="fa-solid fa-brain"></i>}
                {analyzingLogs ? 'Correlating Forensics...' : 'Analyze Evidence Log'}
              </button>
            </div>

            {logAnalysisResult && (
              <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden animate-in fade-in duration-500 shadow-2xl">
                <div className="p-4 bg-slate-800/30 border-b border-slate-800">
                  <h3 className="text-sm font-bold text-emerald-400 uppercase tracking-widest">Forensic Intelligence Report</h3>
                </div>
                <div className="p-6 space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div className="space-y-4">
                      <div>
                        <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Technical Verdict</h4>
                        <p className="text-sm text-slate-300 leading-relaxed bg-slate-950 p-4 rounded-xl border border-slate-800 font-medium italic">
                          {logAnalysisResult.explanation}
                        </p>
                      </div>
                      
                      <div className="pt-4">
                        <div className="flex justify-between items-center mb-4">
                          <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Remediation Checklist</h4>
                          <span className="text-[10px] font-mono text-emerald-400">{logCompletionRate}%</span>
                        </div>
                        
                        <div className="w-full bg-slate-950 h-1.5 rounded-full mb-4 border border-slate-800 overflow-hidden">
                          <div 
                            className="h-full bg-emerald-500 transition-all duration-500" 
                            style={{ width: `${logCompletionRate}%` }}
                          ></div>
                        </div>

                        <ul className="space-y-2">
                          {logAnalysisResult.recommendations.map((rec, i) => (
                            <li 
                              key={i} 
                              onClick={() => toggleLogTask(i)}
                              className={`flex items-start gap-3 p-2 rounded-lg cursor-pointer transition-all border ${
                                completedLogTasks.includes(i) 
                                  ? 'bg-emerald-500/5 border-emerald-500/20 opacity-50' 
                                  : 'bg-slate-950/50 border-slate-800 hover:border-slate-700'
                              }`}
                            >
                              <div className={`mt-0.5 w-4 h-4 rounded flex-shrink-0 flex items-center justify-center border transition-all ${
                                completedLogTasks.includes(i)
                                  ? 'bg-emerald-500 border-emerald-400 text-white'
                                  : 'bg-slate-900 border-slate-700 text-transparent'
                              }`}>
                                <i className="fa-solid fa-check text-[8px]"></i>
                              </div>
                              <span className={`text-[11px] leading-snug ${completedLogTasks.includes(i) ? 'line-through text-slate-500' : 'text-slate-300'}`}>
                                {rec}
                              </span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    <div className="bg-slate-950/50 p-6 rounded-2xl border border-slate-800 shadow-inner">
                      <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-6 text-center">Threat Vector Profile</h4>
                      <div className="h-64 w-full">
                        <ResponsiveContainer width="100%" height="100%">
                          <RadarChart cx="50%" cy="50%" outerRadius="80%" data={logThreatData}>
                            <PolarGrid stroke="#1e293b" />
                            <PolarAngleAxis dataKey="subject" tick={{ fill: '#64748b', fontSize: 10 }} />
                            <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                            <Radar
                              name="Threat Score"
                              dataKey="A"
                              stroke="#10b981"
                              fill="#10b981"
                              fillOpacity={0.5}
                            />
                          </RadarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default IncidentDetail;
