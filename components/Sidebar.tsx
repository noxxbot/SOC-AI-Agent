
import React from 'react';
import { NavLink } from 'react-router-dom';

const Sidebar: React.FC = () => {
  const menuItems = [
    { path: '/', icon: 'fa-chart-line', label: 'Dashboard' },
    { path: '/incidents', icon: 'fa-shield-virus', label: 'Incidents' },
    { path: '/agents', icon: 'fa-server', label: 'Endpoints' },
    { path: '/log-analysis', icon: 'fa-file-code', label: 'Log Analysis' },
    { path: '/detections', icon: 'fa-bell', label: 'Detections' },
    { path: '/threat-intel', icon: 'fa-globe', label: 'Threat Intel' },
    { path: '/live-ops', icon: 'fa-headset', label: 'Live Ops Assistant' },
  ];

  return (
    <div className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-full">
      <div className="p-6">
        <div className="flex items-center gap-3 text-emerald-500 mb-8">
          <div className="w-8 h-8 bg-emerald-500/20 rounded-lg flex items-center justify-center">
            <i className="fa-solid fa-satellite-dish text-xl"></i>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">SENTINEL AI</h1>
        </div>

        <nav className="space-y-2">
          {menuItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${
                  isActive
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100'
                }`
              }
            >
              <i className={`fa-solid ${item.icon} w-5`}></i>
              <span className="font-medium">{item.label}</span>
            </NavLink>
          ))}
        </nav>
      </div>

      <div className="mt-auto p-6 border-t border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center">
            <i className="fa-solid fa-user-secret text-slate-400"></i>
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-200">Senior Analyst</p>
            <p className="text-xs text-slate-500">Tier 3 Responder</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
