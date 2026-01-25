
import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { ProcessedLog } from '../types';

const LogAnalyzer: React.FC = () => {
  const [logs, setLogs] = useState<ProcessedLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [agentFilter, setAgentFilter] = useState('all');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const navigate = useNavigate();

  const severityLabel = (score: number) => {
    if (score >= 90) return 'critical';
    if (score >= 80) return 'high';
    if (score >= 50) return 'medium';
    if (score >= 20) return 'low';
    return 'info';
  };

  const severityStyles: Record<string, string> = {
    critical: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
    high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    low: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    info: 'bg-slate-500/10 text-slate-400 border-slate-500/20'
  };

  const fetchLogs = async (showLoading = false) => {
    if (showLoading) setLoading(true);
    setError(null);
    try {
      const data = await api.getProcessedLogs(100);
      setLogs(data);
      setLastUpdated(new Date());
    } catch (err: any) {
      setError(err?.message || 'Failed to load processed logs.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs(true);
    const interval = setInterval(() => fetchLogs(), 10000);
    return () => clearInterval(interval);
  }, []);

  const categories = useMemo(() => {
    return Array.from(new Set(logs.map((log) => log.category).filter(Boolean))).sort();
  }, [logs]);

  const agents = useMemo(() => {
    return Array.from(new Set(logs.map((log) => log.agent_id).filter(Boolean))).sort();
  }, [logs]);

  const filteredLogs = useMemo(() => {
    const q = search.trim().toLowerCase();
    return logs.filter((log) => {
      const severity = severityLabel(log.severity_score);
      if (categoryFilter !== 'all' && log.category !== categoryFilter) return false;
      if (severityFilter !== 'all' && severity !== severityFilter) return false;
      if (agentFilter !== 'all' && log.agent_id !== agentFilter) return false;
      if (!q) return true;
      const iocs = log.iocs_json || {};
      const iocText = [
        ...(iocs.ips || []),
        ...(iocs.domains || []),
        ...(iocs.sha256 || []),
        ...(iocs.md5 || []),
        ...(iocs.cves || [])
      ].join(' ');
      const tags = (log.tags_json || []).join(' ');
      const haystack = [
        log.message,
        log.hostname,
        log.agent_id,
        log.category,
        log.event_type,
        iocText,
        tags
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [logs, search, categoryFilter, severityFilter, agentFilter]);

  const formatTime = (value: string | null | undefined) => {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold text-slate-50">Log Analysis</h1>
        <div className="flex items-center gap-3 text-slate-500 text-sm">
          <span>Unified processing view across endpoint, DNS, network, auth, system, and application logs</span>
          <span className="text-[10px] font-mono text-slate-600 border-l border-slate-800 pl-3">
            AUTO-REFRESH: 10S {lastUpdated ? `(${lastUpdated.toLocaleTimeString()})` : ''}
          </span>
        </div>
      </header>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
        <div className="flex flex-col lg:flex-row lg:items-center gap-3">
          <div className="flex-1">
            <div className="relative">
              <i className="fa-solid fa-magnifying-glass absolute left-3 top-3 text-slate-500 text-sm"></i>
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search message, hostname, IP, domain"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl py-2.5 pl-9 pr-3 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
              />
            </div>
          </div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200"
          >
            <option value="all">All Categories</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200"
          >
            <option value="all">All Severities</option>
            {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
              <option key={sev} value={sev}>{sev.toUpperCase()}</option>
            ))}
          </select>
          <select
            value={agentFilter}
            onChange={(e) => setAgentFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200"
          >
            <option value="all">All Agents</option>
            {agents.map((agent) => (
              <option key={agent} value={agent}>{agent}</option>
            ))}
          </select>
          <button
            onClick={() => fetchLogs(true)}
            disabled={loading}
            className="bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 px-4 py-2 rounded-xl text-sm flex items-center gap-2 transition-all"
          >
            <i className={`fa-solid fa-rotate ${loading ? 'fa-spin' : ''}`}></i>
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-2xl px-4 py-3 text-rose-300 text-sm">
          {error}
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <table className="w-full text-left border-collapse text-sm">
          <thead className="bg-slate-900/50 border-b border-slate-800">
            <tr className="text-[10px] uppercase tracking-widest text-slate-500">
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Hostname</th>
              <th className="px-4 py-3">Agent</th>
              <th className="px-4 py-3">Category</th>
              <th className="px-4 py-3">Event Type</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Message</th>
              <th className="px-4 py-3">Tags</th>
              <th className="px-4 py-3">IOC Risk</th>
            </tr>
          </thead>
          <tbody>
            {loading && logs.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-6 py-12 text-center text-slate-500">
                  <i className="fa-solid fa-spinner fa-spin text-2xl mb-3"></i>
                  <div className="text-xs uppercase tracking-widest">Loading processed logs</div>
                </td>
              </tr>
            ) : filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-6 py-12 text-center text-slate-500">
                  No logs match the current filters.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => {
                const sev = severityLabel(log.severity_score);
                const rowHighlight = log.severity_score >= 80 ? 'bg-rose-500/5' : '';
                const iocSummary = (log.ioc_intel as any)?.ioc_summary || {};
                const iocRisk = iocSummary?.risk || 'unknown';
                const iocConfidence = typeof iocSummary?.confidence === 'number' ? `${iocSummary.confidence}%` : '—';
                return (
                  <tr
                    key={log.id}
                    onClick={() => navigate(`/log-analysis/${log.id}`)}
                    className={`border-b border-slate-800 hover:bg-slate-800/40 cursor-pointer ${rowHighlight}`}
                  >
                    <td className="px-4 py-3 text-xs text-slate-400">{formatTime(log.timestamp)}</td>
                    <td className="px-4 py-3 text-slate-200">{log.hostname || '—'}</td>
                    <td className="px-4 py-3 text-slate-300">{log.agent_id || '—'}</td>
                    <td className="px-4 py-3 text-slate-300">{log.category}</td>
                    <td className="px-4 py-3 text-slate-400">{log.event_type}</td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] uppercase tracking-widest border px-2 py-1 rounded-full ${severityStyles[sev]}`}>
                        {sev} {log.severity_score}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-200 truncate max-w-[240px]">{log.message}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(log.tags_json || []).slice(0, 3).map((tag, idx) => (
                          <span key={`${log.id}-tag-${idx}`} className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded-full">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-300">
                      <div className="uppercase">{iocRisk}</div>
                      <div className="text-[10px] text-slate-500">{iocConfidence}</div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default LogAnalyzer;
