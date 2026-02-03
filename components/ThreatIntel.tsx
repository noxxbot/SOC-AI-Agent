import React, { useMemo, useState } from 'react';
import { api } from '../services/api';

type ThreatIntelResult = {
  query: string;
  extracted_iocs: {
    cves: string[];
    ips: string[];
    domains: string[];
    sha256: string[];
    md5: string[];
  };
  correlated_alerts: any[];

  external_intel: {
    nvd: any[];
    cisa_kev: any[];
    otx?: any[]; // ✅ Phase 3 added (AlienVault OTX pulses)
  };

  ai_summary: string;

  // (optional fields - some backend versions may send these)
  recommended_actions?: string[];
  mitre_mapping?: any[];
};

type QueryType = 'IOC' | 'MITRE' | 'ANALYST';

type ReportSection = {
  title: string;
  paragraphs: string[];
  items: string[];
};

const ThreatIntel: React.FC = () => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);

  const [result, setResult] = useState<ThreatIntelResult | null>(null);

  const cleanSummary = (text: string) => {
    if (!text) return '';

    let cleaned = text;

    cleaned = cleaned.replace(/```json/gi, '');
    cleaned = cleaned.replace(/```/g, '');

    cleaned = cleaned.replace(/Based on my analysis.*?:/gi, '');

    const trimmed = cleaned.trim();
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      return '';
    }

    return cleaned.trim();
  };

  const normalizeSectionTitle = (title: string) =>
    title.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

  const isIgnoredLine = (line: string) => {
    const trimmed = line.trim();
    if (!trimmed) return true;
    if (/^sentinel intelligence report$/i.test(trimmed)) return true;
    if (/^[ABC]\)\s+/i.test(trimmed)) return true;
    return false;
  };

  const isHeadingLine = (line: string) => {
    const trimmed = line.trim();
    if (!trimmed) return false;
    if (/^#{1,6}\s+/.test(trimmed)) return true;
    if (trimmed.length <= 45 && /:$/.test(trimmed)) return true;
    if (trimmed.length <= 35 && trimmed === trimmed.toUpperCase()) return true;
    return false;
  };

  const extractHeadingTitle = (line: string) => {
    const trimmed = line.trim();
    if (/^#{1,6}\s+/.test(trimmed)) {
      return trimmed.replace(/^#{1,6}\s+/, '').replace(/:$/, '').trim();
    }
    return trimmed.replace(/:$/, '').trim();
  };

  const parseReportSections = (text: string): ReportSection[] => {
    const lines = text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .filter((line) => !isIgnoredLine(line));

    const sections: ReportSection[] = [];
    const sectionMap = new Map<string, ReportSection>();

    const getOrCreate = (title: string) => {
      const key = normalizeSectionTitle(title);
      const existing = sectionMap.get(key);
      if (existing) return existing;
      const section: ReportSection = { title, paragraphs: [], items: [] };
      sectionMap.set(key, section);
      sections.push(section);
      return section;
    };

    let current = getOrCreate('Summary');
    let lastKey = normalizeSectionTitle(current.title);

    lines.forEach((line) => {
      if (isHeadingLine(line)) {
        const title = extractHeadingTitle(line);
        const key = normalizeSectionTitle(title);
        if (key === lastKey) return;
        current = getOrCreate(title);
        lastKey = key;
        return;
      }

      const bulletMatch = line.match(/^[-*•]\s+(.*)$/);
      const numberMatch = line.match(/^\d+\.\s+(.*)$/);
      if (bulletMatch) {
        current.items.push(bulletMatch[1].trim());
        return;
      }
      if (numberMatch) {
        current.items.push(numberMatch[1].trim());
        return;
      }
      current.paragraphs.push(line);
    });

    return sections.filter((section) => section.items.length > 0 || section.paragraphs.length > 0);
  };

  const reportSections = useMemo(() => {
    if (!result?.ai_summary) return [];
    return parseReportSections(cleanSummary(result.ai_summary));
  }, [result?.ai_summary]);

  const recommendedActions = useMemo(() => {
    const actionSectionMatcher = /(recommended actions|recommended|mitigation|response|remediation|next steps|actions)/i;
    const fromSummary = reportSections
      .filter((section) => actionSectionMatcher.test(section.title))
      .flatMap((section) => [...section.items, ...section.paragraphs]);
    const fromPayload = result?.recommended_actions || [];
    const seen = new Set<string>();
    const combined = [...fromPayload, ...fromSummary].filter((action) => {
      const normalized = action.trim().toLowerCase();
      if (!normalized) return false;
      if (seen.has(normalized)) return false;
      seen.add(normalized);
      return true;
    });
    return combined;
  }, [reportSections, result?.recommended_actions]);

  const internalEvidenceItems = useMemo(() => {
    const section = reportSections.find((entry) => /internal evidence/i.test(entry.title));
    if (section) {
      return [...section.paragraphs, ...section.items].filter((item) => item.trim().length > 0);
    }
    if (result?.correlated_alerts?.length) {
      const titles = result.correlated_alerts
        .slice(0, 3)
        .map((alert) => alert?.title)
        .filter(Boolean);
      const items = [`Correlated alerts: ${result.correlated_alerts.length}`];
      if (titles.length > 0) {
        items.push(...titles);
      }
      return items;
    }
    return [];
  }, [reportSections, result?.correlated_alerts]);

  const mitreItems = useMemo(() => {
    if (result?.mitre_mapping?.length) {
      return result.mitre_mapping.map((item) => String(item));
    }
    const section = reportSections.find((entry) => /mitre summary|mitre mapping/i.test(entry.title));
    if (section) {
      return [...section.paragraphs, ...section.items].filter((item) => item.trim().length > 0);
    }
    return [];
  }, [reportSections, result?.mitre_mapping]);

  const displaySections = useMemo(() => {
    const actionSectionMatcher =
      /(recommended actions|recommended|mitigation|response|remediation|next steps|actions|internal evidence|mitre summary|mitre mapping)/i;
    return reportSections.filter((section) => !actionSectionMatcher.test(section.title));
  }, [reportSections]);

  // =========================================================
  // Phase 5 Step 4: Query Type Detection (Frontend)
  // (KEEP WORKING)
  // =========================================================
  const detectQueryType = (q: string): QueryType => {
    const text = (q || '').trim();

    if (!text) return 'ANALYST';

    // IOC patterns
    const isCVE = /CVE-\d{4}-\d{4,7}/i.test(text);
    const isIP = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(text);
    const isHash =
      /\b[a-fA-F0-9]{64}\b/.test(text) || /\b[a-fA-F0-9]{32}\b/.test(text);
    const isDomain = /\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/.test(text);

    if (isCVE || isIP || isHash || isDomain) return 'IOC';

    // MITRE patterns
    const isTechnique = /\bT\d{4}(\.\d{3})?\b/i.test(text); // T1055 or T1055.012
    const isMitreKeyword = /(mitre|attack|tactic|technique)/i.test(text);

    // APT group patterns
    const isAPT = /\bAPT\s?\d{1,3}\b/i.test(text);
    const isKnownGroupAlias = /(olirig|oilrig|lazarus|lockbit|apt38|apt34)/i.test(text);

    if (isTechnique || isMitreKeyword || isAPT || isKnownGroupAlias) return 'MITRE';

    // Otherwise assume analyst question
    return 'ANALYST';
  };

  const queryType = useMemo(() => detectQueryType(query), [query]);

  const queryTypeBadge = useMemo(() => {
    if (queryType === 'IOC') {
      return {
        label: 'A) IOC Query',
        color: 'bg-emerald-600/20 text-emerald-300 border-emerald-500/30',
      };
    }
    if (queryType === 'MITRE') {
      return {
        label: 'B) MITRE Query',
        color: 'bg-indigo-600/20 text-indigo-300 border-indigo-500/30',
      };
    }
    return {
      label: 'C) Analyst Query',
      color: 'bg-amber-600/20 text-amber-300 border-amber-500/30',
    };
  }, [queryType]);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setResult(null);

    try {
      const intel = await api.threatIntelCorrelate(query);
      setResult(intel);
    } catch (error) {
      console.error(error);
      alert('Error fetching threat intel.');
    } finally {
      setLoading(false);
    }
  };

  // ✅ helper safe getters (prevents UI crash)
  const nvdResults = result?.external_intel?.nvd || [];
  const kevResults = result?.external_intel?.cisa_kev || [];
  const otxResults = result?.external_intel?.otx || [];

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      <header className="text-center">
        <h1 className="text-3xl font-bold text-slate-50">Threat Intelligence Lab</h1>
        <p className="text-slate-400 mt-2">
          Correlate your alerts with global real-time vulnerability data and CVE feeds.
        </p>
      </header>

      <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl shadow-xl">
        <form onSubmit={handleSearch} className="relative group">
          <input
            type="text"
            className="w-full bg-slate-950 border-2 border-slate-800 rounded-2xl py-4 pl-12 pr-32 text-slate-200 focus:border-emerald-500 outline-none transition-all placeholder:text-slate-600"
            placeholder="Search CVE, IP Address, Domain, Hash, APT Group, or ask a Blue Team question..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <i className="fa-solid fa-search absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-emerald-500 transition-colors"></i>

          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="absolute right-2 top-2 bottom-2 bg-emerald-600 hover:bg-emerald-500 text-white px-6 rounded-xl font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? <i className="fa-solid fa-circle-notch fa-spin"></i> : 'Gather Intel'}
          </button>
        </form>
      </div>

      {/* ✅ Show empty state only when no result and not loading */}
      {!loading && !result && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 text-slate-400 text-sm">
          Enter a <b className="text-slate-200">CVE</b> / <b className="text-slate-200">IP</b> /{' '}
          <b className="text-slate-200">Domain</b> / <b className="text-slate-200">APT Group</b> or ask a{' '}
          <b className="text-slate-200">Blue Team question</b>, then click{' '}
          <b className="text-slate-200">Gather Intel</b>.
        </div>
      )}

      {/* ===================== */}
      {/* REPORT SECTION */}
      {/* ===================== */}
      {result && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-6 duration-700">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-inner">
            <div className="flex items-center justify-between flex-wrap gap-3 mb-6">
              <h3 className="text-xl font-bold text-emerald-400 flex items-center gap-2">
                <i className="fa-solid fa-brain"></i> Sentinel Intelligence Report
              </h3>

              {/* ✅ ONLY badge here (right side) */}
              <div className={`text-xs px-3 py-1 rounded-full border ${queryTypeBadge.color}`}>
                {queryTypeBadge.label}
              </div>
            </div>

            <div className="space-y-5">
              {displaySections.map((section, sectionIndex) => (
                <div
                  key={`${section.title}-${sectionIndex}`}
                  className="bg-slate-950/40 border border-slate-800 rounded-2xl p-5"
                >
                  <div className="text-xs font-bold text-slate-400 uppercase tracking-[0.2em] mb-3">
                    {section.title}
                  </div>
                  <div className="space-y-3">
                    {section.paragraphs.map((paragraph, paragraphIndex) => (
                      <p key={paragraphIndex} className="text-slate-300 leading-relaxed">
                        {paragraph}
                      </p>
                    ))}
                    {section.items.length > 0 && (
                      <ul className="space-y-2">
                        {section.items.map((item, itemIndex) => (
                          <li key={itemIndex} className="flex gap-2 text-slate-300">
                            <span className="text-emerald-400">•</span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {recommendedActions.length > 0 && (
            <div className="bg-slate-900 border border-emerald-500/30 rounded-2xl p-6 shadow-inner">
              <div className="flex items-center justify-between gap-3 mb-4">
                <h4 className="text-sm font-bold text-emerald-300 uppercase tracking-widest">
                  Recommended Actions
                </h4>
                <span className="text-xs text-emerald-300/70 bg-emerald-500/10 border border-emerald-500/30 px-3 py-1 rounded-full">
                  {recommendedActions.length} Actions
                </span>
              </div>

              <ul className="grid gap-3">
                {recommendedActions.map((action, i) => (
                  <li key={i} className="flex items-start gap-3 text-slate-200">
                    <span className="h-6 w-6 flex items-center justify-center rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-bold">
                      {i + 1}
                    </span>
                    <span className="leading-relaxed">{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {internalEvidenceItems.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <h4 className="text-sm font-bold text-slate-500 uppercase tracking-widest mb-4">
                Internal Evidence
              </h4>
              <ul className="space-y-2 text-slate-300">
                {internalEvidenceItems.map((item, index) => (
                  <li key={index} className="flex gap-2">
                    <span className="text-emerald-400">•</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {mitreItems.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <h4 className="text-sm font-bold text-slate-500 uppercase tracking-widest mb-4">
                MITRE Mapping
              </h4>
              <ul className="space-y-2 text-slate-300">
                {mitreItems.map((item, index) => (
                  <li key={index} className="flex gap-2">
                    <span className="text-indigo-300">•</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.extracted_iocs && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <h4 className="text-sm font-bold text-slate-500 uppercase tracking-widest mb-4">
                Extracted IOCs
              </h4>

              <div className="space-y-3 text-slate-300 text-sm">
                <div>
                  <b>CVEs:</b> {result.extracted_iocs.cves.join(', ') || 'None'}
                </div>
                <div>
                  <b>IPs:</b> {result.extracted_iocs.ips.join(', ') || 'None'}
                </div>
                <div>
                  <b>Domains:</b> {result.extracted_iocs.domains.join(', ') || 'None'}
                </div>
                <div>
                  <b>SHA256:</b> {result.extracted_iocs.sha256.join(', ') || 'None'}
                </div>
                <div>
                  <b>MD5:</b> {result.extracted_iocs.md5.join(', ') || 'None'}
                </div>
              </div>
            </div>
          )}

        </div>
      )}

      {/* ===================== */}
      {/* CORRELATED ALERTS */}
      {/* ===================== */}
      {result?.correlated_alerts?.length > 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="text-sm font-bold text-slate-500 uppercase tracking-widest mb-4">
            Correlated Telemetry Alerts
          </h4>

          <div className="space-y-3">
            {result.correlated_alerts.map((a: any) => (
              <div key={a.id} className="p-4 bg-slate-950/50 border border-slate-800 rounded-xl">
                <div className="text-slate-200 font-bold">{a.title}</div>
                <div className="text-slate-400 text-sm">{a.description}</div>
                <div className="text-xs text-slate-500 mt-2">
                  Severity: {a.severity} | Status: {a.status} | Agent: {a.agent_id}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        result && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <h4 className="text-sm font-bold text-slate-500 uppercase tracking-widest mb-2">
              Correlated Telemetry Alerts
            </h4>
            <p className="text-slate-400 text-sm">No matching alerts found in your database for this query.</p>
          </div>
        )
      )}

      {/* ===================== */}
      {/* EXTERNAL INTEL */}
      {/* ===================== */}
      {result?.external_intel && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <h4 className="text-sm font-bold text-slate-500 uppercase tracking-widest">
            External Threat Intel
          </h4>

          {/* NVD */}
          <div className="text-slate-300 text-sm">
            <div className="flex items-center justify-between">
              <b>NVD Results</b>
              <span className="text-xs text-slate-500">Count: {nvdResults.length}</span>
            </div>

            <pre className="mt-2 bg-slate-950/60 p-3 rounded-xl overflow-auto text-xs border border-slate-800">
              {JSON.stringify(nvdResults, null, 2)}
            </pre>
          </div>

          {/* CISA KEV */}
          <div className="text-slate-300 text-sm">
            <div className="flex items-center justify-between">
              <b>CISA KEV</b>
              <span className="text-xs text-slate-500">Count: {kevResults.length}</span>
            </div>

            <pre className="mt-2 bg-slate-950/60 p-3 rounded-xl overflow-auto text-xs border border-slate-800">
              {JSON.stringify(kevResults, null, 2)}
            </pre>
          </div>

          {/* OTX Pulses */}
          <div className="text-slate-300 text-sm">
            <div className="flex items-center justify-between">
              <b>AlienVault OTX (Community Intel)</b>
              <span className="text-xs text-slate-500">Count: {otxResults.length}</span>
            </div>

            {otxResults.length > 0 ? (
              <div className="mt-3 space-y-3">
                {otxResults.map((p: any, idx: number) => (
                  <div key={idx} className="p-4 bg-slate-950/50 border border-slate-800 rounded-xl">
                    <div className="text-slate-200 font-bold">{p?.name || 'OTX Pulse'}</div>

                    {p?.description && <div className="text-slate-400 text-sm mt-1">{p.description}</div>}

                    <div className="text-xs text-slate-500 mt-2 space-y-1">
                      {p?.author && <div>Author: {p.author}</div>}
                      {p?.created && <div>Created: {String(p.created)}</div>}
                      {p?.modified && <div>Modified: {String(p.modified)}</div>}
                      {p?.tags?.length > 0 && <div>Tags: {p.tags.join(', ')}</div>}
                      {p?.malware_families?.length > 0 && <div>Malware: {p.malware_families.join(', ')}</div>}
                      {p?.references?.length > 0 && (
                        <div>References: {p.references.slice(0, 3).join(' | ')}</div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-slate-400 text-sm mt-2">No OTX pulses found for this query.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatIntel;
