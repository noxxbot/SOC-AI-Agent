import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../services/api';
import { ProcessedLog } from '../types';

const LogDetails: React.FC = () => {
  const { processed_log_id } = useParams();
  const navigate = useNavigate();
  const [log, setLog] = useState<ProcessedLog | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchLog = async () => {
      if (!processed_log_id) {
        setError('No log ID provided.');
        return;
      }
      const logId = Number(processed_log_id);
      if (Number.isNaN(logId)) {
        setError('Invalid log ID.');
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const data = await api.getProcessedLog(logId);
        setLog(data);
      } catch (err: any) {
        setError(err?.message || 'Failed to load log details.');
      } finally {
        setLoading(false);
      }
    };
    fetchLog();
  }, [processed_log_id]);

  const formatTime = (value: string | null | undefined) => {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  };

  const iocIntel = log?.ioc_intel || {};
  const iocSummary = (iocIntel as any)?.ioc_summary || {};
  const iocMatches = (iocIntel as any)?.ioc_matches || [];

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
            <h1 className="text-2xl font-bold text-slate-50">Processed Log Details</h1>
            <p className="text-slate-500 text-sm">Full log context and enrichment metadata</p>
          </div>
        </div>
      </header>

      {error && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-2xl px-4 py-3 text-rose-300 text-sm">
          {error}
        </div>
      )}

      {loading ? (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-10 text-center text-slate-500">
          <i className="fa-solid fa-spinner fa-spin text-2xl mb-3"></i>
          <div className="text-xs uppercase tracking-widest">Loading log details</div>
        </div>
      ) : log ? (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex flex-wrap gap-4 text-xs text-slate-400">
              <span><span className="text-slate-500">Timestamp:</span> {formatTime(log.timestamp)}</span>
              <span><span className="text-slate-500">Agent:</span> {log.agent_id || '—'}</span>
              <span><span className="text-slate-500">Hostname:</span> {log.hostname || '—'}</span>
              <span><span className="text-slate-500">Category:</span> {log.category}</span>
              <span><span className="text-slate-500">Event:</span> {log.event_type}</span>
              <span><span className="text-slate-500">Severity Score:</span> {log.severity_score}</span>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Message</div>
              <div className="text-slate-200 text-sm leading-relaxed">{log.message || 'No message available.'}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Raw Log</div>
              <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs text-slate-300 overflow-auto max-h-64">
                {log.raw || 'No raw log available.'}
              </pre>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-[10px] uppercase tracking-widest text-slate-500">fields_json</div>
              <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs text-slate-300 overflow-auto max-h-80">
                {JSON.stringify(log.fields_json || {}, null, 2)}
              </pre>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-[10px] uppercase tracking-widest text-slate-500">iocs_json</div>
              <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs text-slate-300 overflow-auto max-h-80">
                {JSON.stringify(log.iocs_json || {}, null, 2)}
              </pre>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-[10px] uppercase tracking-widest text-slate-500">MITRE Matches</div>
              <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs text-slate-300 overflow-auto max-h-64">
                {JSON.stringify(log.mitre_matches || [], null, 2)}
              </pre>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-[10px] uppercase tracking-widest text-slate-500">IOC Intel Summary</div>
              <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs text-slate-300 overflow-auto max-h-64">
                {JSON.stringify({ summary: iocSummary, matches: iocMatches }, null, 2)}
              </pre>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-slate-400">
              <div><span className="text-slate-500">Fingerprint:</span> {log.fingerprint || '—'}</div>
              <div><span className="text-slate-500">Created At:</span> {formatTime(log.created_at || null)}</div>
              <div><span className="text-slate-500">Record ID:</span> {log.id}</div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
};

export default LogDetails;
