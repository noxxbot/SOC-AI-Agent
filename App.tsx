
import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useParams } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import LogAnalyzer from './components/LogAnalyzer';
import ThreatIntel from './components/ThreatIntel';
import LiveOps from './components/LiveOps';
import IncidentsList from './components/IncidentsList';
import IncidentDetail from './components/IncidentDetail';
import AgentsList from './components/AgentsList';
import AgentDetail from './components/AgentDetail';
import Detections from './components/Detections';
import LogDetails from './components/LogDetails';
import DetectionDetail from './components/DetectionDetail';
import { Agent, Incident } from './types';
import { api } from './services/api';

const App: React.FC = () => {
  const [notification, setNotification] = useState<{title: string, severity: string} | null>(null);

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.hostname}:8000/ws/notifications`;
    const socket = new WebSocket(wsUrl);

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'NEW_ALERT') {
          setNotification({
            title: payload.data.title,
            severity: payload.data.severity
          });
          setTimeout(() => setNotification(null), 6000);
        }
      } catch (err) {
        console.error('WS Message Parse Error:', err);
      }
    };

    socket.onerror = (error) => console.debug('WebSocket Error:', error);
    
    return () => {
      socket.close();
    };
  }, []);

  const getSeverityColor = (sev: string) => {
    switch(sev.toUpperCase()) {
      case 'CRITICAL': return 'bg-rose-600';
      case 'HIGH': return 'bg-orange-600';
      case 'MEDIUM': return 'bg-yellow-600';
      default: return 'bg-blue-600';
    }
  };

  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-50">
        <Sidebar />
        
        <main className="flex-1 overflow-y-auto p-8 relative">
          {notification && (
            <div className="fixed top-6 left-1/2 -translate-x-1/2 z-50 animate-in slide-in-from-top duration-300">
              <div className={`flex items-center gap-4 px-6 py-4 rounded-2xl shadow-2xl border border-white/10 ${getSeverityColor(notification.severity)}`}>
                <div className="w-8 h-8 rounded-full bg-white/20 flex items-center justify-center">
                  <i className="fa-solid fa-triangle-exclamation text-white"></i>
                </div>
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-widest text-white/70">Critical Alert Detected</p>
                  <p className="text-sm font-bold text-white">{notification.title}</p>
                </div>
                <button 
                  onClick={() => setNotification(null)}
                  className="ml-4 text-white/50 hover:text-white transition-colors"
                >
                  <i className="fa-solid fa-xmark"></i>
                </button>
              </div>
            </div>
          )}

          <div className="absolute top-0 right-0 p-8 flex items-center gap-4 text-xs font-mono text-slate-600 pointer-events-none">
             <span className="flex items-center gap-1">
               <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse"></div>
               SYSTEM: ONLINE
             </span>
             <span className="border-l border-slate-800 pl-4">
               UPTIME: 142:52:11
             </span>
          </div>

          <div className="max-w-7xl mx-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/incidents" element={<IncidentsList />} />
              <Route path="/incidents/:incident_id" element={<IncidentPage />} />
              <Route path="/agents" element={<AgentsPage />} />
              <Route path="/log-analysis" element={<LogAnalyzer />} />
              <Route path="/log-analysis/:processed_log_id" element={<LogDetails />} />
              <Route path="/detections" element={<Detections />} />
              <Route path="/detections/:alert_id" element={<DetectionDetail />} />
              <Route path="/threat-intel" element={<ThreatIntel />} />
              <Route path="/live-ops" element={<LiveOps />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
};

export default App;

const AgentsPage: React.FC = () => {
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);

  const handleSelectAgent = (agent: Agent) => {
    setSelectedAgent(agent);
  };

  const handleBack = () => {
    setSelectedAgent(null);
  };

  return selectedAgent ? (
    <AgentDetail agent={selectedAgent} onBack={handleBack} />
  ) : (
    <AgentsList onSelectAgent={handleSelectAgent} />
  );
};

const IncidentPage: React.FC = () => {
  const { incident_id } = useParams();
  const navigate = useNavigate();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!incident_id) {
      setError('No incident ID provided.');
      return;
    }
    const incidentId = Number(incident_id);
    if (Number.isNaN(incidentId)) {
      setError('Invalid incident ID.');
      return;
    }
    const fetchIncident = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getIncident(incidentId);
        setIncident(data);
      } catch (err: any) {
        setError(err?.message || 'Failed to load incident.');
      } finally {
        setLoading(false);
      }
    };
    fetchIncident();
  }, [incident_id]);

  if (loading) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-10 text-center text-slate-500">
        <i className="fa-solid fa-spinner fa-spin text-2xl mb-3"></i>
        <div className="text-xs uppercase tracking-widest">Loading incident</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-rose-500/10 border border-rose-500/30 rounded-2xl px-4 py-3 text-rose-300 text-sm">
        {error}
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-10 text-center text-slate-500">
        No incident found.
      </div>
    );
  }

  return <IncidentDetail incident={incident} onBack={() => navigate(-1)} />;
};
