
import React, { useState, useEffect, useMemo } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Agent, Telemetry } from '../types';
import { api } from '../services/api';

interface AgentDetailProps {
  agent: Agent;
  onBack: () => void;
}

const AgentDetail: React.FC<AgentDetailProps> = ({ agent, onBack }) => {
  const [telemetry, setTelemetry] = useState<Telemetry[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Filtering states
  const [limit, setLimit] = useState(50);
  const [showCpu, setShowCpu] = useState(true);
  const [showRam, setShowRam] = useState(true);

  const fetchTelemetry = async () => {
    try {
      const data = await api.getTelemetry(agent.agent_id, limit);
      // Backend returns latest first, we need chronological for chart
      setTelemetry([...data].reverse());
    } catch (error) {
      console.error('Failed to fetch telemetry:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
    // Poll every 10 seconds as requested
    const interval = setInterval(fetchTelemetry, 10000);
    return () => clearInterval(interval);
  }, [agent.agent_id, limit]);

  const chartData = useMemo(() => {
    return telemetry.map(t => ({
      time: new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      cpu: t.cpu_percent,
      ram: t.ram_percent
    }));
  }, [telemetry]);

  const latest = telemetry[telemetry.length - 1];

  const timeRangeOptions = [
    { label: 'Latest', value: 30 },
    { label: '15m', value: 60 },
    { label: '1h', value: 240 },
    { label: 'Max (500)', value: 500 },
  ];

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
      <header className="flex items-center gap-4">
        <button 
          onClick={onBack}
          className="w-10 h-10 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400 hover:text-white transition-all shadow-lg"
        >
          <i className="fa-solid fa-arrow-left"></i>
        </button>
        <div>
          <div className="flex items-center gap-3 mb-1">
            <span className="font-mono text-[10px] font-bold text-emerald-500 bg-emerald-500/5 px-2 py-0.5 rounded border border-emerald-500/10 uppercase">
              {agent.agent_id}
            </span>
            <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse"></span>
          </div>
          <h1 className="text-2xl font-bold text-slate-50">{agent.hostname}</h1>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* Utilization Chart with Filters */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
              <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                <i className="fa-solid fa-chart-line text-emerald-500"></i>
                Telemetry Stream
              </h3>
              
              <div className="flex flex-wrap items-center gap-4">
                {/* Metric Toggles */}
                <div className="flex items-center bg-slate-950/50 p-1 rounded-lg border border-slate-800">
                  <button 
                    onClick={() => setShowCpu(!showCpu)}
                    className={`px-3 py-1 rounded text-[10px] font-bold transition-all ${showCpu ? 'bg-emerald-500/20 text-emerald-400' : 'text-slate-600'}`}
                  >
                    CPU
                  </button>
                  <button 
                    onClick={() => setShowRam(!showRam)}
                    className={`px-3 py-1 rounded text-[10px] font-bold transition-all ${showRam ? 'bg-blue-500/20 text-blue-400' : 'text-slate-600'}`}
                  >
                    RAM
                  </button>
                </div>

                {/* Time Range Select */}
                <div className="flex items-center bg-slate-950/50 p-1 rounded-lg border border-slate-800">
                  {timeRangeOptions.map((opt) => (
                    <button
                      key={opt.value}
                      onClick={() => setLimit(opt.value)}
                      className={`px-3 py-1 rounded text-[10px] font-bold transition-all ${limit === opt.value ? 'bg-slate-800 text-slate-100 shadow-sm' : 'text-slate-500 hover:text-slate-300'}`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            
            <div className="h-80 w-full relative">
              {loading && telemetry.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-600">
                   <i className="fa-solid fa-circle-notch fa-spin text-2xl mb-4 text-emerald-500"></i>
                   <p className="font-mono text-xs uppercase tracking-widest">Establishing telemetry uplink...</p>
                </div>
              ) : chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                    <XAxis 
                      dataKey="time" 
                      stroke="#64748b" 
                      fontSize={10} 
                      tickLine={false} 
                      axisLine={false}
                      minTickGap={40}
                    />
                    <YAxis 
                      stroke="#64748b" 
                      fontSize={10} 
                      tickLine={false} 
                      axisLine={false} 
                      domain={[0, 100]}
                      tickFormatter={(val) => `${val}%`}
                    />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '12px' }}
                      itemStyle={{ fontSize: '12px' }}
                    />
                    {showCpu && (
                      <Line 
                        type="monotone" 
                        dataKey="cpu" 
                        stroke="#10b981" 
                        strokeWidth={2} 
                        dot={false} 
                        animationDuration={300}
                        name="CPU Usage"
                      />
                    )}
                    {showRam && (
                      <Line 
                        type="monotone" 
                        dataKey="ram" 
                        stroke="#3b82f6" 
                        strokeWidth={2} 
                        dot={false} 
                        animationDuration={300}
                        name="RAM Usage"
                      />
                    )}
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-slate-700 italic text-sm">
                   No telemetry data received from agent in the specified window.
                </div>
              )}
              
              {/* Metric Overlay Labels for clarity */}
              <div className="absolute bottom-2 right-4 flex gap-4 pointer-events-none">
                 {showCpu && <span className="text-[9px] font-mono text-emerald-500/50 uppercase">CPU TRACKING</span>}
                 {showRam && <span className="text-[9px] font-mono text-blue-500/50 uppercase">RAM TRACKING</span>}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 gap-6">
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg text-center transition-all hover:border-emerald-500/30">
              <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">CPU LOAD</h4>
              <p className="text-3xl font-bold text-emerald-500">{latest ? Math.round(latest.cpu_percent) : '--'}%</p>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg text-center transition-all hover:border-blue-500/30">
              <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">MEMORY</h4>
              <p className="text-3xl font-bold text-blue-500">{latest ? Math.round(latest.ram_percent) : '--'}%</p>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg text-center transition-all hover:border-slate-600/30">
              <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">PROCESSES</h4>
              <p className="text-3xl font-bold text-slate-200">{latest ? latest.process_count : '--'}</p>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-6">Agent Details</h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center pb-3 border-b border-slate-800">
                <span className="text-sm text-slate-400">Hostname</span>
                <span className="text-sm font-medium text-slate-200">{agent.hostname}</span>
              </div>
              <div className="flex justify-between items-center pb-3 border-b border-slate-800">
                <span className="text-sm text-slate-400">IP Address</span>
                <span className="text-sm font-mono text-slate-200">{agent.ip_address}</span>
              </div>
              <div className="flex justify-between items-center pb-3 border-b border-slate-800">
                <span className="text-sm text-slate-400">Platform</span>
                <span className="text-sm font-medium text-slate-200">{agent.os}</span>
              </div>
              <div className="flex justify-between items-center pb-3 border-b border-slate-800">
                <span className="text-sm text-slate-400">Agent ID</span>
                <span className="text-[10px] font-mono text-slate-500">{agent.agent_id}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-slate-400">Last Check-in</span>
                <span className="text-sm font-medium text-emerald-500">{new Date(agent.last_seen).toLocaleTimeString()}</span>
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Quick Actions</h3>
            <div className="space-y-2">
              <button className="w-full flex items-center gap-3 p-3 rounded-xl border border-slate-800 hover:bg-slate-800 text-sm transition-all group shadow-sm">
                <i className="fa-solid fa-terminal text-slate-500 group-hover:text-emerald-400"></i>
                <span className="text-slate-300">Open Shell Session</span>
              </button>
              <button className="w-full flex items-center gap-3 p-3 rounded-xl border border-slate-800 hover:bg-slate-800 text-sm transition-all group shadow-sm">
                <i className="fa-solid fa-rotate-right text-slate-500 group-hover:text-emerald-400"></i>
                <span className="text-slate-300">Force Update Agent</span>
              </button>
              <button className="w-full flex items-center gap-3 p-3 rounded-xl border border-rose-500/20 hover:bg-rose-500/10 text-sm transition-all group shadow-md">
                <i className="fa-solid fa-ban text-rose-500"></i>
                <span className="text-rose-400 font-medium">Isolate Endpoint</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AgentDetail;
