
import React, { useState, useEffect } from 'react';
import { offlineAnalyzeLog } from "../services/offlineAnalyzer";
import { analyzeLog } from "../services/gemini";
import { AnalysisResult } from '../types';

const LogAnalyzer: React.FC = () => {
  const [logs, setLogs] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [completedTasks, setCompletedTasks] = useState<number[]>([]);

  const handleAnalyze = async () => {
  if (!logs.trim()) return;

  setLoading(true);
  setCompletedTasks([]);

  try {
    // 1) Try AI (Gemini) first
    const aiResult = await analyzeLog(logs);
    setResult(aiResult);
  } catch (error) {
    console.warn("Gemini failed, switching to Offline Analyzer...", error);

    // 2) If AI fails, fallback to Offline rules
    const offlineResult = offlineAnalyzeLog(logs);
    setResult(offlineResult);
  } finally {
    setLoading(false);
  }
};

  const toggleTask = (index: number) => {
    setCompletedTasks(prev => 
      prev.includes(index) ? prev.filter(i => i !== index) : [...prev, index]
    );
  };

  const getRiskColor = (score: number) => {
    if (score > 75) return 'text-rose-500';
    if (score > 40) return 'text-amber-500';
    return 'text-emerald-500';
  };

  const completionRate = result ? Math.round((completedTasks.length / result.recommendations.length) * 100) : 0;

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <header>
        <h1 className="text-3xl font-bold text-slate-50">AI Forensic Log Analyzer</h1>
        <p className="text-slate-400">Deep inspection of raw system, network, or application logs using Gemini 3.</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <label className="block text-sm font-medium text-slate-400 mb-2 uppercase tracking-widest font-bold text-[10px]">Log Evidence Input</label>
            <textarea
              className="w-full h-96 bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-sm text-slate-300 focus:ring-2 focus:ring-emerald-500/50 outline-none transition-all resize-none"
              placeholder="Example: 2023-10-27 10:14:52 Failed login for root from 192.168.1.15..."
              value={logs}
              onChange={(e) => setLogs(e.target.value)}
            />
            <button
              onClick={handleAnalyze}
              disabled={loading || !logs.trim()}
              className={`mt-4 w-full py-3 rounded-xl font-semibold flex items-center justify-center gap-2 transition-all shadow-lg ${
                loading ? 'bg-slate-800 text-slate-500 cursor-not-allowed' : 'bg-emerald-600 hover:bg-emerald-500 text-white'
              }`}
            >
              {loading ? (
                <><i className="fa-solid fa-circle-notch fa-spin"></i> Analyzing Evidence...</>
              ) : (
                <><i className="fa-solid fa-magnifying-glass-chart"></i> Run Security Analysis</>
              )}
            </button>
          </div>
        </div>

        <div className="space-y-4">
          {!result && !loading ? (
            <div className="h-full flex flex-col items-center justify-center bg-slate-900/50 border-2 border-dashed border-slate-800 rounded-2xl p-12 text-center text-slate-500">
              <i className="fa-solid fa-microchip text-4xl mb-4 opacity-20"></i>
              <p>Analysis report will appear here once logs are submitted</p>
            </div>
          ) : loading ? (
            <div className="h-full flex flex-col items-center justify-center bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center">
              <div className="animate-pulse flex flex-col items-center">
                <div className="w-16 h-16 bg-emerald-500/20 rounded-full flex items-center justify-center mb-6">
                  <i className="fa-solid fa-shield-halved text-2xl text-emerald-500"></i>
                </div>
                <h4 className="text-xl font-semibold text-slate-200 mb-2 uppercase tracking-tighter">Sentinel AI is Thinking</h4>
                <p className="text-slate-400 text-sm">Scanning for SQL injection, lateral movement, and credential theft...</p>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden animate-in fade-in slide-in-from-bottom-4 duration-500 shadow-2xl">
              <div className="p-6 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 className="font-semibold text-lg">Forensic Report</h3>
                <div className="flex items-center gap-2 px-3 py-1 bg-slate-800 rounded-full border border-slate-700">
                  <span className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">Risk Level</span>
                  <span className={`font-mono font-bold ${getRiskColor(result.riskScore)}`}>{result.riskScore}/100</span>
                </div>
              </div>
              
              <div className="p-6 space-y-6">
                <div>
                  <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Threat Assessment</h4>
                  <div className={`flex items-center gap-2 font-bold uppercase text-xs p-3 rounded-lg border ${result.threatDetected ? 'text-rose-400 bg-rose-400/5 border-rose-400/20' : 'text-emerald-400 bg-emerald-400/5 border-emerald-400/20'}`}>
                    <i className={`fa-solid ${result.threatDetected ? 'fa-triangle-exclamation' : 'fa-circle-check'}`}></i>
                    {result.threatDetected ? 'Critical Vulnerability Confirmed' : 'No Critical Threats Detected'}
                  </div>
                </div>

                <div>
                  <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Findings Details</h4>
                  <p className="text-slate-300 leading-relaxed bg-slate-950 p-4 rounded-xl border border-slate-800 text-sm font-medium italic">"{result.explanation}"</p>
                </div>

                <div className="pt-4 border-t border-slate-800/50">
                  <div className="flex justify-between items-end mb-4">
                    <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Remediation Roadmap</h4>
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded border border-emerald-500/20">{completionRate}% COMPLETE</span>
                  </div>
                  
                  {/* Progress Bar */}
                  <div className="w-full bg-slate-950 h-2 rounded-full mb-6 border border-slate-800 overflow-hidden">
                    <div 
                      className="h-full bg-emerald-500 transition-all duration-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]" 
                      style={{ width: `${completionRate}%` }}
                    ></div>
                  </div>

                  <div className="space-y-3">
                    {result.recommendations.map((rec, i) => (
                      <button 
                        key={i} 
                        onClick={() => toggleTask(i)}
                        className={`w-full flex gap-3 p-3 rounded-xl border transition-all text-left group ${
                          completedTasks.includes(i) 
                            ? 'bg-emerald-500/5 border-emerald-500/20 text-slate-400' 
                            : 'bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-200'
                        }`}
                      >
                        <div className={`flex-shrink-0 w-6 h-6 rounded-lg flex items-center justify-center border transition-all ${
                          completedTasks.includes(i)
                            ? 'bg-emerald-500 border-emerald-400 text-white'
                            : 'bg-slate-900 border-slate-700 group-hover:border-slate-500 text-transparent'
                        }`}>
                          <i className="fa-solid fa-check text-[10px]"></i>
                        </div>
                        <span className={`text-xs font-medium leading-relaxed ${completedTasks.includes(i) ? 'line-through opacity-50' : ''}`}>
                          {rec}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default LogAnalyzer;
