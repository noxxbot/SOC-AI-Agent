import React, { useEffect, useState } from 'react';
import { Incident } from '../types';
import { api } from '../services/api';

const IncidentsList: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastSync, setLastSync] = useState<Date | null>(null);

  const fetchIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getRecentIncidents(20);
      setIncidents(data);
      setLastSync(new Date());
    } catch (err: any) {
      setError(err?.message || 'Failed to load incidents.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const formatTime = (value?: string | null) => {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  };

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-slate-50">Incidents</h1>
          <p className="text-slate-500 text-sm">Recent incidents linked to detection alerts</p>
          {lastSync && (
            <div className="text-[10px] font-mono text-slate-600 mt-1">LAST SYNC: {lastSync.toLocaleTimeString()}</div>
          )}
        </div>
        <button
          onClick={fetchIncidents}
          disabled={loading}
          className="bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 px-4 py-2 rounded-xl text-sm flex items-center gap-2 transition-all"
        >
          <i className={`fa-solid fa-rotate ${loading ? 'fa-spin' : ''}`}></i>
          Refresh
        </button>
      </header>

      {error && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-2xl px-4 py-3 text-rose-300 text-sm">
          {error}
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl min-h-[400px]">
        <table className="w-full text-left border-collapse text-sm">
          <thead className="bg-slate-900/50 border-b border-slate-800">
            <tr className="text-[10px] uppercase tracking-widest text-slate-500">
              <th className="px-4 py-3">Incident</th>
              <th className="px-4 py-3">Created</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Linked Alerts</th>
              <th className="px-4 py-3">Summary</th>
            </tr>
          </thead>
          <tbody>
            {loading && incidents.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-slate-500">
                  <i className="fa-solid fa-spinner fa-spin text-2xl mb-3"></i>
                  <div className="text-xs uppercase tracking-widest">Loading incidents</div>
                </td>
              </tr>
            ) : incidents.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-slate-500">
                  No incidents available.
                </td>
              </tr>
            ) : (
              incidents.map((incident) => (
                <tr key={incident.id} className="border-b border-slate-800">
                  <td className="px-4 py-3">
                    <div className="text-xs font-mono text-emerald-400">INC-{incident.id}</div>
                    <div className="text-slate-200">{incident.title || 'Untitled incident'}</div>
                  </td>
                  <td className="px-4 py-3 text-slate-400">{formatTime(incident.created_at)}</td>
                  <td className="px-4 py-3 text-slate-300 uppercase">{incident.severity || 'unknown'}</td>
                  <td className="px-4 py-3 text-slate-300">
                    {(incident.related_alert_ids || []).length > 0
                      ? (incident.related_alert_ids || []).join(', ')
                      : '—'}
                  </td>
                  <td className="px-4 py-3 text-slate-300 truncate max-w-[320px]">{incident.summary || 'No summary available.'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default IncidentsList;
