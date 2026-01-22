
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Incident, Severity } from '../types';
import { api } from '../services/api';

interface IncidentsListProps {
  onSelectIncident: (incident: Incident) => void;
}

const IncidentsList: React.FC<IncidentsListProps> = ({ onSelectIncident }) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);
  const [analyzingIds, setAnalyzingIds] = useState<Set<string>>(new Set());
  const [lastSync, setLastSync] = useState<Date>(new Date());
  const [sortBy, setSortBy] = useState<'timestamp' | 'riskScore' | 'severity' | 'priority'>('timestamp');

  const fetchAlerts = useCallback(async (showLoading = false) => {
    if (showLoading) setLoading(true);
    try {
      const data = await api.getAlerts();
      setIncidents(prev => {
        const existingDataMap = new Map(prev.map(i => [i.id, { riskScore: i.riskScore, priority: i.priority }]));
        return data.map(inc => ({
          ...inc,
          riskScore: existingDataMap.get(inc.id)?.riskScore ?? inc.riskScore,
          priority: existingDataMap.get(inc.id)?.priority ?? inc.priority
        }));
      });
      setLastSync(new Date());
    } catch (error) {
      console.error('Fetch Alerts Error:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts(true);
    const interval = setInterval(() => fetchAlerts(), 30000);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  const calculateAutoPriority = (severity: Severity, riskScore?: number): 'P1' | 'P2' | 'P3' | 'P4' => {
    if (severity === Severity.CRITICAL || (riskScore !== undefined && riskScore > 80)) return 'P1';
    if (severity === Severity.HIGH || (riskScore !== undefined && riskScore > 60)) return 'P2';
    if (severity === Severity.MEDIUM || (riskScore !== undefined && riskScore > 30)) return 'P3';
    return 'P4';
  };

  const handlePriorityOverride = (e: React.ChangeEvent<HTMLSelectElement>, incidentId: string) => {
    e.stopPropagation();
    const newPriority = e.target.value as 'P1' | 'P2' | 'P3' | 'P4';
    setIncidents(prev => prev.map(inc => 
      inc.id === incidentId ? { ...inc, priority: newPriority } : inc
    ));
  };

  const handleRunAIAnalysis = async (e: React.MouseEvent, incident: Incident) => {
    e.stopPropagation();
    const numericId = parseInt(incident.id.replace('ALR-', ''));
    if (isNaN(numericId)) return;

    setAnalyzingIds(prev => new Set(prev).add(incident.id));
    try {
      const result = await api.analyzeAlert(numericId);
      setIncidents(prev => prev.map(inc => 
        inc.id === incident.id ? { ...inc, riskScore: result.riskScore } : inc
      ));
    } catch (error) {
      console.error('AI Analysis failed:', error);
    } finally {
      setAnalyzingIds(prev => {
        const next = new Set(prev);
        next.delete(incident.id);
        return next;
      });
    }
  };

  const getSeverityPriority = (sev: Severity) => {
    switch (sev) {
      case Severity.CRITICAL: return 4;
      case Severity.HIGH: return 3;
      case Severity.MEDIUM: return 2;
      case Severity.LOW: return 1;
      default: return 0;
    }
  };

  const getPriorityWeight = (p?: 'P1' | 'P2' | 'P3' | 'P4') => {
    switch (p) {
      case 'P1': return 4;
      case 'P2': return 3;
      case 'P3': return 2;
      case 'P4': return 1;
      default: return 0;
    }
  };

  const filteredAndSortedIncidents = useMemo(() => {
    let result = incidents.filter(inc => 
      inc.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.id.toLowerCase().includes(searchTerm.toLowerCase())
    );

    result.sort((a, b) => {
      if (sortBy === 'riskScore') {
        return (b.riskScore || 0) - (a.riskScore || 0);
      }
      if (sortBy === 'severity') {
        return getSeverityPriority(b.severity) - getSeverityPriority(a.severity);
      }
      if (sortBy === 'priority') {
        const pa = a.priority || calculateAutoPriority(a.severity, a.riskScore);
        const pb = b.priority || calculateAutoPriority(b.severity, b.riskScore);
        return getPriorityWeight(pb) - getPriorityWeight(pa);
      }
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });

    return result;
  }, [incidents, searchTerm, sortBy]);

  const getPriorityStyles = (p: 'P1' | 'P2' | 'P3' | 'P4', isOverride: boolean) => {
    const base = "text-[10px] font-bold px-2 py-1 rounded-lg border uppercase tracking-wider flex items-center gap-1.5 transition-all ";
    const overrideIndicator = isOverride ? "shadow-[0_0_8px_rgba(16,185,129,0.2)] border-emerald-500/40" : "border-transparent";
    
    switch (p) {
      case 'P1': return base + `bg-rose-500/20 text-rose-400 ${overrideIndicator}`;
      case 'P2': return base + `bg-orange-500/20 text-orange-400 ${overrideIndicator}`;
      case 'P3': return base + `bg-amber-500/20 text-amber-400 ${overrideIndicator}`;
      case 'P4': return base + `bg-slate-800 text-slate-400 ${overrideIndicator}`;
      default: return base + "bg-slate-800 text-slate-500";
    }
  };

  const getSeverityStyles = (severity: Severity) => {
    switch (severity) {
      case Severity.CRITICAL: return 'bg-rose-500/10 text-rose-500 border-rose-500/20';
      case Severity.HIGH: return 'bg-orange-500/10 text-orange-500 border-orange-500/20';
      case Severity.MEDIUM: return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
      case Severity.LOW: return 'bg-blue-500/10 text-blue-500 border-blue-500/20';
      default: return 'bg-slate-500/10 text-slate-500 border-slate-500/20';
    }
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-50 flex items-center gap-3">
            Incident Command Center
            <span className="text-xs font-mono bg-emerald-500/10 text-emerald-500 px-2 py-1 rounded border border-emerald-500/20">LIVE</span>
          </h1>
          <div className="flex items-center gap-2 text-slate-400 mt-1">
            <p>Intelligence-driven alert prioritization and management</p>
            <span className="text-[10px] font-mono text-slate-600 border-l border-slate-800 pl-2">
              LAST SYNC: {lastSync.toLocaleTimeString()}
            </span>
          </div>
        </div>
        <div className="flex flex-wrap gap-3">
          <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-1 shadow-inner">
            <button 
              onClick={() => setSortBy('timestamp')}
              className={`px-3 py-1.5 text-[10px] font-bold uppercase rounded-md transition-all ${sortBy === 'timestamp' ? 'bg-slate-800 text-emerald-400 shadow-sm' : 'text-slate-500 hover:text-slate-300'}`}
            >
              Time
            </button>
            <button 
              onClick={() => setSortBy('priority')}
              className={`px-3 py-1.5 text-[10px] font-bold uppercase rounded-md transition-all ${sortBy === 'priority' ? 'bg-slate-800 text-emerald-400 shadow-sm' : 'text-slate-500 hover:text-slate-300'}`}
            >
              Priority
            </button>
            <button 
              onClick={() => setSortBy('severity')}
              className={`px-3 py-1.5 text-[10px] font-bold uppercase rounded-md transition-all ${sortBy === 'severity' ? 'bg-slate-800 text-emerald-400 shadow-sm' : 'text-slate-500 hover:text-slate-300'}`}
            >
              Severity
            </button>
            <button 
              onClick={() => setSortBy('riskScore')}
              className={`px-3 py-1.5 text-[10px] font-bold uppercase rounded-md transition-all ${sortBy === 'riskScore' ? 'bg-slate-800 text-emerald-400 shadow-sm' : 'text-slate-500 hover:text-slate-300'}`}
            >
              Risk
            </button>
          </div>
          <div className="relative">
            <i className="fa-solid fa-search absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm"></i>
            <input 
              type="text" 
              placeholder="Filter by ID or Title..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm focus:border-emerald-500 outline-none transition-all w-64 placeholder:text-slate-600 shadow-lg"
            />
          </div>
          <button 
            onClick={() => fetchAlerts(true)}
            disabled={loading}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded-lg text-sm font-semibold transition-all flex items-center gap-2 border border-slate-700 shadow-lg"
          >
            <i className={`fa-solid fa-rotate ${loading ? 'fa-spin' : ''}`}></i>
          </button>
        </div>
      </header>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl min-h-[500px]">
        {loading && incidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[500px] text-slate-500">
            <div className="relative mb-6">
               <div className="absolute inset-0 bg-emerald-500/20 blur-xl rounded-full"></div>
               <i className="fa-solid fa-satellite-dish text-4xl text-emerald-500 relative animate-pulse"></i>
            </div>
            <p className="font-mono text-xs uppercase tracking-widest text-slate-400">Synchronizing Intelligence Cloud...</p>
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50">
                <th className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Incident</th>
                <th className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Priority (Override)</th>
                <th className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Baseline</th>
                <th className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">AI Status</th>
                <th className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Detected</th>
                <th className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filteredAndSortedIncidents.map((incident) => {
                const effectivePriority = incident.priority || calculateAutoPriority(incident.severity, incident.riskScore);
                return (
                  <tr 
                    key={incident.id} 
                    onClick={() => onSelectIncident(incident)}
                    className="hover:bg-slate-800/30 transition-all group cursor-pointer"
                  >
                    <td className="px-6 py-4">
                      <div className="flex flex-col gap-1">
                        <span className="font-mono text-[10px] font-bold text-emerald-500 bg-emerald-500/5 px-2 py-0.5 rounded border border-emerald-500/10 w-fit">
                          {incident.id}
                        </span>
                        <div className="font-medium text-slate-200 truncate group-hover:text-emerald-400 transition-colors">
                          {incident.title}
                        </div>
                        <div className="text-[10px] text-slate-500 flex items-center gap-2">
                          <i className="fa-solid fa-server text-[8px]"></i>
                          {incident.source}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="relative group/priority">
                          <div className={getPriorityStyles(effectivePriority, !!incident.priority)}>
                            <i className="fa-solid fa-flag text-[9px]"></i>
                            {effectivePriority}
                            {!incident.priority && <i className="fa-solid fa-robot text-[8px] opacity-40 ml-1"></i>}
                          </div>
                          
                          {/* Hidden Select for Analyst Override */}
                          <select 
                            onClick={(e) => e.stopPropagation()}
                            onChange={(e) => handlePriorityOverride(e, incident.id)}
                            value={incident.priority || ''}
                            className="absolute inset-0 opacity-0 cursor-pointer w-full"
                          >
                            <option value="">Auto (Reset)</option>
                            <option value="P1">P1 - Critical</option>
                            <option value="P2">P2 - High</option>
                            <option value="P3">P3 - Medium</option>
                            <option value="P4">P4 - Low</option>
                          </select>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`text-[10px] font-bold px-2 py-1 rounded border uppercase tracking-tighter ${getSeverityStyles(incident.severity)}`}>
                        {incident.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      {incident.riskScore !== undefined ? (
                        <div 
                          className="flex items-center gap-2 text-emerald-500 font-bold text-[10px] uppercase bg-emerald-500/5 px-2 py-1 rounded-full w-fit border border-emerald-500/10"
                          title={`Intelligence Confirmation: ${incident.riskScore}%`}
                        >
                          <i className="fa-solid fa-microchip text-[9px]"></i>
                          {incident.riskScore}%
                        </div>
                      ) : (
                        <button 
                          onClick={(e) => handleRunAIAnalysis(e, incident)}
                          disabled={analyzingIds.has(incident.id)}
                          className="flex items-center gap-2 px-3 py-1 bg-slate-800/50 hover:bg-emerald-500/20 text-slate-500 hover:text-emerald-400 border border-slate-700 hover:border-emerald-500/30 rounded-lg text-[9px] font-bold uppercase transition-all"
                        >
                          {analyzingIds.has(incident.id) ? (
                            <><i className="fa-solid fa-spinner fa-spin"></i> Analyzing</>
                          ) : (
                            <><i className="fa-solid fa-bolt"></i> Triage</>
                          )}
                        </button>
                      )}
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-400 whitespace-nowrap">
                      {incident.timestamp}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button className="w-8 h-8 rounded-full flex items-center justify-center text-slate-600 hover:text-emerald-400 hover:bg-emerald-500/5 transition-all">
                        <i className="fa-solid fa-chevron-right text-xs"></i>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="flex justify-between items-center text-xs text-slate-500 font-mono px-2 pt-2">
        <div className="flex gap-4">
           <p>TRIAGE QUEUE: {filteredAndSortedIncidents.length}</p>
           <p>OVERRIDDEN: {incidents.filter(i => i.priority).length}</p>
        </div>
        <div className="flex gap-4 items-center">
          <span className="flex items-center gap-2">
            <div className="w-2 h-2 rounded bg-rose-500"></div> P1
          </span>
          <span className="flex items-center gap-2">
            <div className="w-2 h-2 rounded bg-orange-500"></div> P2
          </span>
          <span className="flex items-center gap-2 border-l border-slate-800 pl-4">
            <i className="fa-solid fa-robot text-[10px] text-emerald-500"></i> AI RANKED
          </span>
          <span className="flex items-center gap-2">
             <div className="w-2 h-2 rounded border border-emerald-500 shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div> MANUAL OVERRIDE
          </span>
        </div>
      </div>
    </div>
  );
};

export default IncidentsList;
