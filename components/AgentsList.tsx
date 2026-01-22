
import React, { useState, useEffect, useCallback } from 'react';
import { Agent } from '../types';
import { api } from '../services/api';

interface AgentsListProps {
  onSelectAgent: (agent: Agent) => void;
}

const AgentsList: React.FC<AgentsListProps> = ({ onSelectAgent }) => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastSync, setLastSync] = useState<Date>(new Date());

  const fetchAgents = useCallback(async (showLoading = false) => {
    if (showLoading) setLoading(true);
    try {
      const data = await api.getAgents();
      setAgents(data);
      setLastSync(new Date());
    } catch (error) {
      console.error('Failed to fetch agents:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents(true);
    const interval = setInterval(() => fetchAgents(), 10000);
    return () => clearInterval(interval);
  }, [fetchAgents]);

  const isOnline = (lastSeen: string) => {
    const lastSeenDate = new Date(lastSeen);
    const now = new Date();
    // Consider online if seen in the last 60 seconds
    return (now.getTime() - lastSeenDate.getTime()) < 60000;
  };

  return (
    <div className="space-y-6">
      <header className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-slate-50">Managed Endpoints</h1>
          <div className="flex items-center gap-2 text-slate-400 mt-1">
            <p>Inventory of all active security agents across the infrastructure</p>
            <span className="text-[10px] font-mono text-slate-600 border-l border-slate-800 pl-2">
              AUTO-SYNC: 10S ({lastSync.toLocaleTimeString()})
            </span>
          </div>
        </div>
        <button 
          onClick={() => fetchAgents(true)}
          disabled={loading}
          className="bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition-all shadow-lg"
        >
          <i className={`fa-solid fa-arrows-rotate ${loading ? 'fa-spin' : ''}`}></i>
          Manual Refresh
        </button>
      </header>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl min-h-[400px]">
        {loading && agents.length === 0 ? (
          <div className="p-20 text-center text-slate-500 h-[400px] flex flex-col items-center justify-center">
            <i className="fa-solid fa-spinner fa-spin text-3xl mb-4 text-emerald-500"></i>
            <p className="font-mono text-xs uppercase tracking-widest">Polling Fleet Controllers...</p>
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50">
                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-widest">Hostname</th>
                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-widest">IP Address</th>
                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-widest">OS</th>
                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-widest">Status</th>
                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-widest text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {agents.map((agent) => (
                <tr 
                  key={agent.id} 
                  onClick={() => onSelectAgent(agent)}
                  className="hover:bg-slate-800/30 transition-colors group cursor-pointer"
                >
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${isOnline(agent.last_seen) ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-slate-700'}`}></div>
                      <span className="font-semibold text-slate-200 group-hover:text-emerald-400 transition-colors">{agent.hostname}</span>
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 mt-1 uppercase">{agent.agent_id}</div>
                  </td>
                  <td className="px-6 py-4 text-sm font-mono text-slate-400">
                    {agent.ip_address}
                  </td>
                  <td className="px-6 py-4 text-xs text-slate-300">
                    <i className={`fa-brands ${agent.os.toLowerCase().includes('win') ? 'fa-windows' : 'fa-linux'} mr-2`}></i>
                    {agent.os}
                  </td>
                  <td className="px-6 py-4 text-xs text-slate-400">
                    {isOnline(agent.last_seen) ? 
                      <span className="text-emerald-500 font-bold uppercase tracking-tighter">ONLINE</span> : 
                      `Last seen: ${new Date(agent.last_seen).toLocaleTimeString()}`}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="text-slate-500 hover:text-emerald-400 transition-colors">
                      <i className="fa-solid fa-chevron-right"></i>
                    </button>
                  </td>
                </tr>
              ))}
              {agents.length === 0 && !loading && (
                <tr>
                  <td colSpan={5} className="px-6 py-20 text-center text-slate-600">
                    <i className="fa-solid fa-ghost text-4xl mb-4 opacity-20"></i>
                    <p>No managed endpoints detected in the fleet.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default AgentsList;
