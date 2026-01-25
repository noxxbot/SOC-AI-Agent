import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Alert } from '../types';

const Detections: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const fetchAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getDetectionAlerts(100);
      setAlerts(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load detections.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-slate-50">Detections</h1>
          <p className="text-slate-500 text-sm">Rule engine alerts with evidence, MITRE mapping, and IOC context</p>
        </div>
        <button
          onClick={fetchAlerts}
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

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <table className="w-full text-left border-collapse text-sm">
          <thead className="bg-slate-900/50 border-b border-slate-800">
            <tr className="text-[10px] uppercase tracking-widest text-slate-500">
              <th className="px-4 py-3">Rule</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Confidence</th>
              <th className="px-4 py-3">Summary</th>
              <th className="px-4 py-3">MITRE</th>
              <th className="px-4 py-3">IOC Matches</th>
              <th className="px-4 py-3">Investigated</th>
            </tr>
          </thead>
          <tbody>
            {loading && alerts.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-slate-500">
                  <i className="fa-solid fa-spinner fa-spin text-2xl mb-3"></i>
                  <div className="text-xs uppercase tracking-widest">Loading detections</div>
                </td>
              </tr>
            ) : alerts.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-slate-500">
                  No detection alerts available.
                </td>
              </tr>
            ) : (
              alerts.map((alert) => (
                <tr
                  key={alert.id}
                  onClick={() => navigate(`/detections/${alert.id}`)}
                  className="border-b border-slate-800 hover:bg-slate-800/40 cursor-pointer"
                >
                  <td className="px-4 py-3">
                    <div className="text-xs font-mono text-emerald-400">{alert.rule_id}</div>
                    <div className="text-slate-200">{alert.rule_name}</div>
                  </td>
                  <td className="px-4 py-3 text-slate-300 uppercase">{alert.severity}</td>
                  <td className="px-4 py-3 text-slate-300">{alert.confidence_score}</td>
                  <td className="px-4 py-3 text-slate-200 truncate max-w-[240px]">{alert.summary || 'No summary'}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {(alert.mitre || []).slice(0, 3).map((item: any, idx: number) => (
                        <span key={`${alert.id}-mitre-${idx}`} className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded-full">
                          {item.technique_id || item.id} {item.name || item.technique_name}
                        </span>
                      ))}
                      {(alert.mitre || []).length === 0 && (
                        <span className="text-[10px] text-slate-500">None</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {(alert.ioc_matches || []).length}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`text-[10px] uppercase tracking-widest px-2 py-0.5 rounded-full border ${
                        alert.investigated
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {alert.investigated ? 'YES' : 'NO'}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Detections;
