
import React, { useState, useEffect, useMemo } from 'react';
import { Incident, Severity, Playbook, AnalysisResult, BriefingResult, Telemetry, CorrelationResult } from '../types';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer } from 'recharts';
import { api } from '../services/api';

interface IncidentDetailProps {
  incident: Incident;
  onBack: () => void;
}

const normalizeVectorValue = (value: unknown) => {
  if (typeof value === 'number') return value;
  if (typeof value === 'boolean') return value ? 80 : 15;
  return 0;
};

const buildBriefingResult = (analysis: AnalysisResult, incident: Incident): BriefingResult => {
  const briefParts = [
    incident.title ? `Incident focus: ${incident.title}` : null,
    incident.summary ? incident.summary : null,
    analysis.explanation ? analysis.explanation : null
  ].filter(Boolean);

  if (analysis.recommendations?.length) {
    briefParts.push(`Recommended actions:\n${analysis.recommendations.slice(0, 6).map((rec, idx) => `${idx + 1}. ${rec}`).join('\n')}`);
  }

  const vectors = analysis.threatVectors || {
    persistence: 0,
    lateralMovement: 0,
    exfiltration: 0,
    reconnaissance: 0,
    credentialAccess: 0
  };

  return {
    brief: briefParts.join('\n'),
    vectors: {
      persistence: normalizeVectorValue(vectors.persistence),
      lateralMovement: normalizeVectorValue(vectors.lateralMovement),
      exfiltration: normalizeVectorValue(vectors.exfiltration),
      reconnaissance: normalizeVectorValue(vectors.reconnaissance),
      credentialAccess: normalizeVectorValue(vectors.credentialAccess)
    }
  };
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
  const [briefingResult, setBriefingResult] = useState<BriefingResult | null>(null);
  const [loadingBrief, setLoadingBrief] = useState(false);

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
    const fetchBrief = async () => {
      setLoadingBrief(true);
      try {
        const briefInput = [incident.title, incident.summary, incident.source, incident.agentId, incident.agent_id]
          .filter(Boolean)
          .join('\n');
        const analysis = await api.analyzeLogs(briefInput || 'Incident briefing request');
        setBriefingResult(buildBriefingResult(analysis, incident));
      } catch (e) {
        console.error("Brief generation failed", e);
      } finally {
        setLoadingBrief(false);
      }
    };
    fetchBrief();
  }, [incident]);

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

  const briefingThreatData = briefingResult?.vectors ? [
    { subject: 'Persistence', A: briefingResult.vectors.persistence, fullMark: 100 },
    { subject: 'Lateral Movement', A: briefingResult.vectors.lateralMovement, fullMark: 100 },
    { subject: 'Exfiltration', A: briefingResult.vectors.exfiltration, fullMark: 100 },
    { subject: 'Reconnaissance', A: briefingResult.vectors.reconnaissance, fullMark: 100 },
    { subject: 'Cred Access', A: briefingResult.vectors.credentialAccess, fullMark: 100 },
  ] : [];

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
                {loadingBrief && <i className="fa-solid fa-circle-notch fa-spin text-emerald-500 text-xs"></i>}
              </div>
              <div className="p-6">
                {loadingBrief ? (
                  <div className="animate-pulse space-y-2">
                    <div className="h-4 bg-slate-800 rounded w-3/4"></div>
                    <div className="h-4 bg-slate-800 rounded w-1/2"></div>
                  </div>
                ) : briefingResult ? (
                  <div className="grid grid-cols-1 md:grid-cols-5 gap-6">
                    <div className="md:col-span-3 prose prose-sm prose-invert max-w-none">
                      {briefingResult.brief.split('\n').map((para, i) => (
                        <p key={i} className="text-slate-300 mb-2 last:mb-0 leading-relaxed">
                          {para}
                        </p>
                      ))}
                    </div>
                    <div className="md:col-span-2 bg-slate-950/40 p-4 rounded-xl border border-slate-800/50">
                       <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4 text-center">Threat Vector Profile</h4>
                       <div className="h-48 w-full">
                          <ResponsiveContainer width="100%" height="100%">
                            <RadarChart cx="50%" cy="50%" outerRadius="70%" data={briefingThreatData}>
                              <PolarGrid stroke="#1e293b" />
                              <PolarAngleAxis dataKey="subject" tick={{ fill: '#64748b', fontSize: 8 }} />
                              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                              <Radar
                                name="Incident Vector"
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
                ) : (
                   <p className="text-slate-500 text-sm">Waiting for briefing correlation...</p>
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
                    <p className="text-sm animate-pulse">Sentinel AI is drafting hunting procedures...</p>
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
                  {incident.timestamp}
                </div>
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
                      <p className="text-xs text-slate-400 mt-1">{incident.timestamp}</p>
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
