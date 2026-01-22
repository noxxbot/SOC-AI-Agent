
import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { api } from '../services/api';
import { Severity } from '../types';

const data = [
  { time: '00:00', alerts: 45, severity: 12 },
  { time: '04:00', alerts: 52, severity: 18 },
  { time: '08:00', alerts: 88, severity: 45 },
  { time: '12:00', alerts: 120, severity: 67 },
  { time: '16:00', alerts: 95, severity: 38 },
  { time: '20:00', alerts: 65, severity: 24 },
  { time: '23:59', alerts: 40, severity: 15 },
];

const StatCard = ({ label, value, trend, icon, color }: any) => (
  <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl">
    <div className="flex justify-between items-start mb-4">
      <div className={`w-12 h-12 rounded-xl flex items-center justify-center bg-${color}-500/10 text-${color}-500`}>
        <i className={`fa-solid ${icon} text-xl`}></i>
      </div>
      <span className={`text-sm ${trend.startsWith('+') ? 'text-rose-500' : 'text-emerald-500'}`}>
        {trend} <i className={`fa-solid ${trend.startsWith('+') ? 'fa-arrow-trend-up' : 'fa-arrow-trend-down'} ml-1`}></i>
      </span>
    </div>
    <h3 className="text-slate-400 text-sm font-medium mb-1">{label}</h3>
    <p className="text-3xl font-bold text-slate-50">{value}</p>
  </div>
);

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState({
    agentsOnline: 0,
    criticalAlerts: 0,
    totalAlerts: 0
  });

  useEffect(() => {
    const fetchDashboardStats = async () => {
      try {
        const [agents, alerts] = await Promise.all([
          api.getAgents(),
          api.getAlerts()
        ]);
        
        const now = new Date().getTime();
        const online = agents.filter(a => (now - new Date(a.last_seen).getTime()) < 60000).length;
        const critical = alerts.filter(a => a.severity === Severity.CRITICAL || a.severity === Severity.HIGH).length;

        setStats({
          agentsOnline: online,
          criticalAlerts: critical,
          totalAlerts: alerts.length
        });
      } catch (err) {
        console.error("Dashboard Stats Fetch Error:", err);
      }
    };

    fetchDashboardStats();
    const interval = setInterval(fetchDashboardStats, 10000);
    return () => clearInterval(interval);
  }, []);

  const severityDistribution = [
    { name: 'Critical/High', value: stats.criticalAlerts, color: '#ef4444' },
    { name: 'Total Alerts', value: stats.totalAlerts, color: '#3b82f6' },
    { name: 'Endpoints', value: stats.agentsOnline, color: '#10b981' },
  ];

  return (
    <div className="space-y-8">
      <header className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-slate-50">Operations Overview</h1>
          <p className="text-slate-400">Real-time status of security infrastructure</p>
        </div>
        <div className="bg-emerald-500/5 border border-emerald-500/10 px-4 py-2 rounded-xl flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
          <span className="text-xs font-mono text-emerald-500 uppercase tracking-widest font-bold">Live Stream: Active</span>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard label="Endpoints Active" value={stats.agentsOnline} trend="+2" icon="fa-server" color="emerald" />
        <StatCard label="High/Critical" value={stats.criticalAlerts} trend={stats.criticalAlerts > 0 ? "+1" : "0"} icon="fa-triangle-exclamation" color="rose" />
        <StatCard label="Total Alert Count" value={stats.totalAlerts} trend="+12" icon="fa-bolt" color="blue" />
        <StatCard label="Network Security" value="98%" trend="stable" icon="fa-shield-halved" color="amber" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-2xl">
          <div className="flex justify-between items-center mb-6">
            <h3 className="text-lg font-semibold">Anomaly Activity (24h)</h3>
            <div className="text-[10px] font-mono text-slate-600">UNITS: AGGREGATED_ALERTS</div>
          </div>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data}>
                <defs>
                  <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '12px' }}
                  itemStyle={{ color: '#f8fafc' }}
                />
                <Area type="monotone" dataKey="alerts" stroke="#10b981" fillOpacity={1} fill="url(#colorAlerts)" strokeWidth={3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-2xl">
          <h3 className="text-lg font-semibold mb-6">Fleet Distribution</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityDistribution} layout="vertical">
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} width={80} />
                <Tooltip 
                   cursor={{fill: 'transparent'}}
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '12px' }}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {severityDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 p-4 bg-slate-950/50 rounded-xl border border-slate-800">
             <p className="text-[10px] text-slate-500 uppercase font-bold mb-2">Health Consensus</p>
             <div className="flex items-center gap-2">
                <i className="fa-solid fa-circle-check text-emerald-500 text-xs"></i>
                <span className="text-xs text-slate-300">Overall fleet health is within nominal parameters.</span>
             </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
