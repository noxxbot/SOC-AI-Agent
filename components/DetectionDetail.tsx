import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../services/api';
import { Alert, Investigation } from '../types';

const DetectionDetail: React.FC = () => {
  const { alert_id } = useParams();
  const navigate = useNavigate();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runLoading, setRunLoading] = useState(false);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [investigationError, setInvestigationError] = useState<string | null>(null);
  const [expandedInvestigationId, setExpandedInvestigationId] = useState<number | null>(null);

  useEffect(() => {
    const fetchAlert = async () => {
      if (!alert_id) {
        setError('No alert ID provided.');
        return;
      }
      const alertId = Number(alert_id);
      if (Number.isNaN(alertId)) {
        setError('Invalid alert ID.');
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const data = await api.getDetectionAlert(alertId);
        setAlert(data);
      } catch (err: any) {
        setError(err?.message || 'Failed to load detection details.');
      } finally {
        setLoading(false);
      }
    };
    fetchAlert();
  }, [alert_id]);

  const fetchInvestigations = async (alertId: number, silent: boolean = false) => {
    if (!silent) {
      setInvestigationLoading(true);
    }
    setInvestigationError(null);
    try {
      const data = await api.getInvestigations(alertId);
      setInvestigations(data);
    } catch {
      setInvestigationError('Failed to load investigations');
      setInvestigations([]);
    } finally {
      if (!silent) {
        setInvestigationLoading(false);
      }
    }
  };

  useEffect(() => {
    if (alert?.id) {
      fetchInvestigations(alert.id);
    }
  }, [alert?.id]);

  const shouldPollInvestigations = useMemo(() => {
    return investigations.some((inv) => {
      const status = (inv.status || '').toLowerCase();
      return status === 'running' || status === 'pending';
    });
  }, [investigations]);

  useEffect(() => {
    if (!alert?.id || !shouldPollInvestigations) {
      return undefined;
    }
    const interval = setInterval(() => {
      fetchInvestigations(alert.id, true);
    }, 8000);
    return () => clearInterval(interval);
  }, [alert?.id, shouldPollInvestigations]);

  const handleRunInvestigation = async () => {
    if (!alert) return;
    setRunLoading(true);
    setInvestigationError(null);
    try {
      await api.runInvestigation(alert.id, true);
      await fetchInvestigations(alert.id);
    } catch (err: any) {
      setInvestigationError(err?.message || 'Failed to run investigation');
    } finally {
      setRunLoading(false);
    }
  };

  const latestInvestigation = useMemo(() => investigations[0], [investigations]);
  const latestDetails = latestInvestigation?.investigation || {};
  const isIncident = latestInvestigation?.is_incident ?? false;
  const incidentSeverity = isIncident ? latestInvestigation?.incident_severity || 'low' : 'none';
  const incidentId = useMemo(() => {
    const raw = alert?.incident_id ?? (alert?.evidence as any)?.incident_id;
    if (typeof raw === 'number') return raw;
    if (typeof raw === 'string' && raw.trim()) {
      const parsed = Number(raw);
      return Number.isNaN(parsed) ? null : parsed;
    }
    return null;
  }, [alert]);
  const latestTimeline = useMemo(() => {
    const timeline = (latestDetails as any)?.timeline;
    if (!Array.isArray(timeline)) return [];
    return timeline
      .map((item: any) => {
        if (!item) return '';
        if (typeof item === 'string') return item;
        if (typeof item === 'object') {
          const timestamp = item.timestamp || item.time;
          const event = item.event || item.activity;
          const source = item.source || item.log_source;
          return [timestamp, event, source].filter(Boolean).join(' — ');
        }
        return String(item);
      })
      .filter((value: string) => value && value.trim().length > 0);
  }, [latestDetails]);
  const formatTimestamp = (value?: string | null) => {
    if (!value) return 'Unknown time';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return 'Unknown time';
    return date.toLocaleString();
  };
  const getStatusBadge = (status?: string | null) => {
    const normalized = (status || '').toLowerCase();
    if (normalized === 'completed') {
      return { label: 'COMPLETED', className: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' };
    }
    if (normalized === 'failed' || normalized === 'error') {
      return { label: 'FAILED', className: 'bg-rose-500/20 text-rose-300 border-rose-500/30' };
    }
    return { label: 'RUNNING', className: 'bg-amber-500/20 text-amber-300 border-amber-500/30' };
  };
  const getSeverityBadge = (value?: string | null) => {
    const normalized = (value || 'none').toLowerCase();
    if (normalized === 'critical') return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
    if (normalized === 'high') return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
    if (normalized === 'medium') return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
    if (normalized === 'low') return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
    return 'bg-slate-800 text-slate-400 border-slate-700';
  };
  const getIocVerdictLabel = (value: any) => {
    if (!value) return 'No IOC verdicts';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    const indicator = value?.ioc || value?.indicator || value?.value || 'IOC';
    const verdict = value?.verdict || value?.label || value?.decision;
    if (verdict) return `${indicator}: ${verdict}`;
    return JSON.stringify(value);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <header className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate(-1)}
            className="w-10 h-10 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400 hover:text-white hover:border-slate-700 transition-all shadow-lg"
          >
            <i className="fa-solid fa-arrow-left"></i>
          </button>
          <div>
            <h1 className="text-2xl font-bold text-slate-50">Detection Details</h1>
            <p className="text-slate-500 text-sm">Alert evidence, MITRE mapping, and AI investigation output</p>
          </div>
        </div>
        {incidentId ? (
          <button
            onClick={() => navigate(`/incidents/${incidentId}`)}
            className="bg-slate-900 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10 hover:border-emerald-500/60 px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all"
          >
            <i className="fa-solid fa-shield-halved"></i>
            View Incident
          </button>
        ) : null}
      </header>

      {error && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-2xl px-4 py-3 text-rose-300 text-sm">
          {error}
        </div>
      )}

      {loading ? (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-10 text-center text-slate-500">
          <i className="fa-solid fa-spinner fa-spin text-2xl mb-3"></i>
          <div className="text-xs uppercase tracking-widest">Loading detection details</div>
        </div>
      ) : alert ? (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
            <div>
              <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Summary</div>
              <div className="text-slate-200 text-sm leading-relaxed">{alert.summary || 'No summary available.'}</div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-slate-400">
              <div><span className="text-slate-500">Rule:</span> {alert.rule_id} {alert.rule_name}</div>
              <div><span className="text-slate-500">Severity:</span> {alert.severity}</div>
              <div><span className="text-slate-500">Confidence:</span> {alert.confidence_score}</div>
              <div><span className="text-slate-500">Category:</span> {alert.category}</div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-[10px] uppercase tracking-widest text-slate-500">Evidence</div>
              <div className="text-xs text-slate-400 space-y-2">
                <div><span className="text-slate-500">Processed IDs:</span> {(alert.evidence?.processed_ids || []).join(', ') || 'None'}</div>
                <div><span className="text-slate-500">Fingerprints:</span> {(alert.evidence?.fingerprints || []).join(', ') || 'None'}</div>
              </div>
              <div className="text-[10px] uppercase tracking-widest text-slate-500">IOC Matches</div>
              <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs text-slate-300 overflow-auto max-h-64">
                {JSON.stringify(alert.ioc_matches || [], null, 2)}
              </pre>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-[10px] uppercase tracking-widest text-slate-500">MITRE Mapping</div>
              <div className="flex flex-wrap gap-2">
                {(alert.mitre || []).map((item: any, idx: number) => (
                  <span key={`mitre-${idx}`} className="text-[10px] bg-slate-800 text-slate-300 px-2 py-1 rounded-full">
                    {item.technique_id || item.id} {item.name || item.technique_name}
                  </span>
                ))}
                {(alert.mitre || []).length === 0 && (
                  <span className="text-xs text-slate-500">No MITRE techniques listed.</span>
                )}
              </div>
              <div className="text-[10px] uppercase tracking-widest text-slate-500">Recommended Actions</div>
              {(alert.recommended_actions || []).length === 0 ? (
                <div className="text-xs text-slate-500">No recommended actions available.</div>
              ) : (
                <ul className="space-y-1 text-xs text-slate-300">
                  {(alert.recommended_actions || []).map((action, idx) => (
                    <li key={`rec-${idx}`} className="flex gap-2">
                      <span className="text-emerald-400">•</span>
                      <span>{action}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <div className="text-[10px] uppercase tracking-widest text-slate-500">AI Investigation</div>
                <div className="text-sm text-slate-400">Run or review the latest AI investigation for this alert.</div>
              </div>
              <button
                onClick={handleRunInvestigation}
                disabled={runLoading}
                className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all"
              >
                <i className={`fa-solid ${runLoading ? 'fa-spinner fa-spin' : 'fa-magnifying-glass-chart'}`}></i>
                Run AI Investigation
              </button>
            </div>

            {investigationLoading ? (
              <div className="text-xs text-slate-500">Loading investigations...</div>
            ) : investigationError ? (
              <div className="text-xs text-rose-300">{investigationError}</div>
            ) : latestInvestigation ? (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
                  <div className="text-[10px] uppercase tracking-widest text-slate-500">Summary</div>
                  <div className="text-sm text-slate-200">{latestDetails.summary || 'No summary available.'}</div>
                  <div className="text-[10px] uppercase tracking-widest text-slate-500">Case Notes</div>
                  <pre className="bg-slate-900 border border-slate-800 rounded-xl p-3 text-xs text-slate-300 whitespace-pre-wrap">
                    {latestDetails.case_notes || 'No case notes.'}
                  </pre>
                  <div className="text-[10px] uppercase tracking-widest text-slate-500">Explainability</div>
                  {(latestDetails.explainability || []).length === 0 ? (
                    <div className="text-xs text-slate-500">No explainability notes.</div>
                  ) : (
                    <ul className="space-y-1 text-xs text-slate-300">
                      {(latestDetails.explainability || []).map((item: string, idx: number) => (
                        <li key={`exp-${idx}`} className="flex gap-2">
                          <span className="text-emerald-400">•</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
                  <div className="text-[10px] uppercase tracking-widest text-slate-500">Assessment</div>
                  <div className="text-xs text-slate-400 space-y-2">
                    <div><span className="text-slate-500">Confidence Score:</span> {latestInvestigation.confidence_score}</div>
                    <div><span className="text-slate-500">Is Incident:</span> {isIncident ? 'true' : 'false'}</div>
                    <div><span className="text-slate-500">Incident Severity:</span> {incidentSeverity}</div>
                  </div>
                  <div className="text-[10px] uppercase tracking-widest text-slate-500">Confidence Breakdown</div>
                  {Object.keys(latestDetails.confidence_breakdown || {}).length === 0 ? (
                    <div className="text-xs text-slate-500">No confidence breakdown.</div>
                  ) : (
                    <div className="space-y-2 text-xs text-slate-300">
                      {Object.entries(latestDetails.confidence_breakdown || {}).map(([key, value]) => (
                        <div key={key} className="flex justify-between bg-slate-900/60 border border-slate-800 rounded-lg px-3 py-2">
                          <span className="uppercase tracking-widest text-slate-400">{key.replace(/_/g, ' ')}</span>
                          <span>{value}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="text-[10px] uppercase tracking-widest text-slate-500">Recommended Actions</div>
                  {(latestDetails.recommended_actions || []).length === 0 ? (
                    <div className="text-xs text-slate-500">No recommended actions.</div>
                  ) : (
                    <ul className="space-y-1 text-xs text-slate-300">
                      {(latestDetails.recommended_actions || []).map((action: string, idx: number) => (
                        <li key={`ai-rec-${idx}`} className="flex gap-2">
                          <span className="text-emerald-400">•</span>
                          <span>{action}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                  <div className="text-[10px] uppercase tracking-widest text-slate-500">Timeline</div>
                  {latestTimeline.length === 0 ? (
                    <div className="text-xs text-slate-500">No timeline entries.</div>
                  ) : (
                    <ul className="space-y-1 text-xs text-slate-300">
                      {latestTimeline.map((item: string, idx: number) => (
                        <li key={`ai-timeline-${idx}`} className="flex gap-2">
                          <span className="text-emerald-400">•</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-500">No investigations yet.</div>
            )}
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="text-[10px] uppercase tracking-widest text-slate-500">Investigation History</div>
            {investigationLoading ? (
              <div className="text-xs text-slate-500">Loading investigations...</div>
            ) : investigationError ? (
              <div className="text-xs text-rose-300">Failed to load investigations</div>
            ) : investigations.length === 0 ? (
              <div className="space-y-3">
                <div className="text-xs text-slate-500">No investigations yet.</div>
                <button
                  onClick={handleRunInvestigation}
                  disabled={runLoading}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all w-fit"
                >
                  <i className={`fa-solid ${runLoading ? 'fa-spinner fa-spin' : 'fa-magnifying-glass-chart'}`}></i>
                  Run AI Investigation
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                {investigations.map((inv, index) => {
                  const isLatestEntry = index === 0;
                  const details = inv.investigation || {};
                  const summary = details.summary || 'No summary available.';
                  const statusBadge = getStatusBadge(inv.status);
                  const incidentFlag = inv.is_incident ?? details.is_incident ?? false;
                  const severity = incidentFlag ? inv.incident_severity || details.incident_severity || 'low' : 'none';
                  const confidenceScore = details.confidence_score ?? inv.confidence_score ?? 0;
                  const mitreTop = (details.mitre_mapping || [])[0];
                  const iocTop = (details.ioc_verdicts || [])[0];
                  const isExpanded = expandedInvestigationId === inv.id;
                  return (
                    <div
                      key={inv.id}
                      className={`border rounded-2xl p-4 space-y-3 ${isLatestEntry ? 'border-emerald-500/40 bg-emerald-500/5' : 'border-slate-800 bg-slate-950/40'}`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div className="flex items-center gap-3 text-xs text-slate-400">
                          <span>{formatTimestamp(inv.created_at)}</span>
                          {isLatestEntry && (
                            <span className="text-[10px] uppercase tracking-widest bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded-full">
                              Latest
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] uppercase tracking-widest border px-2 py-0.5 rounded-full ${statusBadge.className}`}>
                            {statusBadge.label}
                          </span>
                          <button
                            onClick={() => setExpandedInvestigationId(isExpanded ? null : inv.id)}
                            className="text-[10px] uppercase tracking-widest text-slate-400 hover:text-white border border-slate-800 hover:border-slate-700 px-2 py-1 rounded-full transition-all"
                          >
                            {isExpanded ? 'Hide Details' : 'View Details'}
                          </button>
                        </div>
                      </div>
                      <div className="text-sm text-slate-200 truncate">{summary}</div>
                      {['failed', 'error'].includes((inv.status || '').toLowerCase()) ? (
                        <div className="text-xs text-rose-300">AI failed – manual review needed</div>
                      ) : null}
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span
                          className={`border px-2 py-0.5 rounded-full ${incidentFlag ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : 'bg-slate-800 text-slate-400 border-slate-700'}`}
                        >
                          Is Incident: {incidentFlag ? 'true' : 'false'}
                        </span>
                        <span className={`border px-2 py-0.5 rounded-full ${getSeverityBadge(severity)}`}>
                          Incident Severity: {severity}
                        </span>
                        <span className="border border-slate-800 text-slate-300 px-2 py-0.5 rounded-full">
                          Confidence: {confidenceScore}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-2 text-xs text-slate-400">
                        <div className="flex items-center gap-2">
                          <span className="text-slate-500">Top MITRE:</span>
                          <span className="text-slate-300">
                            {mitreTop
                              ? `${mitreTop.technique_id || mitreTop.id || ''} ${mitreTop.name || mitreTop.technique_name || ''}`.trim() || 'Unknown technique'
                              : 'No MITRE techniques'}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-slate-500">Top IOC Verdict:</span>
                          <span className="text-slate-300">{getIocVerdictLabel(iocTop)}</span>
                        </div>
                      </div>
                      {isExpanded && (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-3 border-t border-slate-800">
                          <div className="space-y-3">
                            <div>
                              <div className="text-[10px] uppercase tracking-widest text-slate-500">Case Notes</div>
                              <pre className="bg-slate-900 border border-slate-800 rounded-xl p-3 text-xs text-slate-300 whitespace-pre-wrap">
                                {details.case_notes || 'No case notes.'}
                              </pre>
                            </div>
                            <div>
                              <div className="text-[10px] uppercase tracking-widest text-slate-500">Recommended Actions</div>
                              {(details.recommended_actions || []).length === 0 ? (
                                <div className="text-xs text-slate-500">No recommended actions.</div>
                              ) : (
                                <ul className="space-y-1 text-xs text-slate-300">
                                  {(details.recommended_actions || []).map((action: string, idx: number) => (
                                    <li key={`history-rec-${inv.id}-${idx}`} className="flex gap-2">
                                      <span className="text-emerald-400">•</span>
                                      <span>{action}</span>
                                    </li>
                                  ))}
                                </ul>
                              )}
                            </div>
                          </div>
                          <div className="space-y-3">
                            <div>
                              <div className="text-[10px] uppercase tracking-widest text-slate-500">Explainability</div>
                              {(details.explainability || []).length === 0 ? (
                                <div className="text-xs text-slate-500">No explainability notes.</div>
                              ) : (
                                <ul className="space-y-1 text-xs text-slate-300">
                                  {(details.explainability || []).map((item: string, idx: number) => (
                                    <li key={`history-exp-${inv.id}-${idx}`} className="flex gap-2">
                                      <span className="text-emerald-400">•</span>
                                      <span>{item}</span>
                                    </li>
                                  ))}
                                </ul>
                              )}
                            </div>
                            <div>
                              <div className="text-[10px] uppercase tracking-widest text-slate-500">Confidence Breakdown</div>
                              {Object.keys(details.confidence_breakdown || {}).length === 0 ? (
                                <div className="text-xs text-slate-500">No confidence breakdown.</div>
                              ) : (
                                <div className="space-y-2 text-xs text-slate-300">
                                  {Object.entries(details.confidence_breakdown || {}).map(([key, value]) => (
                                    <div key={`${inv.id}-${key}`} className="flex justify-between bg-slate-900/60 border border-slate-800 rounded-lg px-3 py-2">
                                      <span className="uppercase tracking-widest text-slate-400">{key.replace(/_/g, ' ')}</span>
                                      <span>{value as any}</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
};

export default DetectionDetail;
