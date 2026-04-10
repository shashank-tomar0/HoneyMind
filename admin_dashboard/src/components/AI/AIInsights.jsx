import React, { useMemo } from 'react';
import useThreatStore from '../../store/threatStore';
import './AIInsights.css';

const PROFILE_COLORS = {
  'Script Kiddie':           '#22c55e',
  'Automated Bot':           '#3b82f6',
  'Opportunistic Attacker':  '#fbbf24',
  'Advanced Persistent Threat': '#ef4444',
  'Insider Threat':          '#a855f7',
  'Researcher / Pen Tester': '#06b6d4',
};

const ATTACK_LABELS = [
  'SQL_INJECTION', 'XSS', 'BRUTE_FORCE', 'COMMAND_INJECTION',
  'DIRECTORY_TRAVERSAL', 'RECON', 'DATA_EXFILTRATION', 'PRIVILEGE_ESCALATION',
];

export default function AIInsights() {
  const { feedEvents, stats } = useThreatStore();

  const latestClassified = useMemo(() =>
    feedEvents.find((e) => e.attack_type && e.attack_type !== 'UNKNOWN'),
    [feedEvents]
  );

  const profileDist = useMemo(() => {
    const p = stats.attacker_profiles || {};
    const total = Object.values(p).reduce((a, b) => a + b, 0) || 1;
    return Object.entries(p)
      .map(([label, count]) => ({
        label, count,
        pct: Math.round((count / total) * 100),
        color: PROFILE_COLORS[label] || '#6b7280',
      }))
      .sort((a, b) => b.count - a.count);
  }, [stats.attacker_profiles]);

  const attackTypeDist = useMemo(() => {
    const counts = {};
    feedEvents.forEach((e) => { if (e.attack_type) counts[e.attack_type] = (counts[e.attack_type] || 0) + 1; });
    const total = feedEvents.length || 1;
    return ATTACK_LABELS.map((t) => ({
      type: t.replace(/_/g, ' '),
      count: counts[t] || 0,
      pct: Math.round(((counts[t] || 0) / total) * 100),
    })).sort((a, b) => b.count - a.count);
  }, [feedEvents]);

  return (
    <div className="ai-insights glass-card">
      <div className="ai-header">
        <span className="text-sm font-bold glow-cyan">🧠 AI Analysis</span>
        <span className="dim text-xs mono">LIVE</span>
      </div>

      <div className="ai-body">
        {/* Latest classification */}
        {latestClassified && (
          <div className="ai-section">
            <div className="section-title mono text-xs dim">LATEST CLASSIFICATION</div>
            <div className="latest-card">
              <div className="latest-type" style={{ color: 'var(--cyan)' }}>
                {latestClassified.attack_type?.replace(/_/g, ' ')}
              </div>
              <div className="confidence-bar-wrapper">
                <div className="confidence-bar-track">
                  <div
                    className="confidence-bar-fill"
                    style={{ width: `${latestClassified.classification_confidence || 0}%` }}
                  />
                </div>
                <span className="mono text-xs" style={{ color: 'var(--cyan)' }}>
                  {latestClassified.classification_confidence?.toFixed(1)}%
                </span>
              </div>
              <div className="latest-meta dim text-xs mono">
                Anomaly: {latestClassified.anomaly_score?.toFixed(0)}% ·
                Profile: {latestClassified.attacker_profile}
              </div>
            </div>
          </div>
        )}

        {/* Attacker profiles */}
        {profileDist.length > 0 && (
          <div className="ai-section">
            <div className="section-title mono text-xs dim">ATTACKER PROFILES</div>
            <div className="profile-list">
              {profileDist.map((p) => (
                <div key={p.label} className="profile-row">
                  <span className="profile-dot" style={{ background: p.color }} />
                  <span className="text-xs" style={{ flex: 1, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {p.label}
                  </span>
                  <div className="profile-bar-track">
                    <div className="profile-bar-fill" style={{ width: `${p.pct}%`, background: p.color }} />
                  </div>
                  <span className="mono text-xs" style={{ color: p.color, width: 30, textAlign: 'right' }}>
                    {p.count}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Attack type bars */}
        <div className="ai-section">
          <div className="section-title mono text-xs dim">ATTACK TYPE HEATMAP</div>
          <div className="heatmap">
            {attackTypeDist.map((t) => (
              <div key={t.type} className="heatmap-cell"
                title={`${t.type}: ${t.count} events (${t.pct}%)`}
                style={{
                  background: t.pct > 0
                    ? `rgba(0,240,255,${Math.min(0.9, 0.1 + t.pct * 0.02)})`
                    : 'var(--bg-elevated)',
                  borderColor: t.pct > 20 ? 'var(--cyan-glow)' : 'var(--border)',
                }}
              >
                <div className="heatmap-label mono" style={{ fontSize: 9 }}>
                  {t.type.slice(0, 6).toUpperCase()}
                </div>
                <div className="heatmap-count mono text-xs" style={{ color: 'var(--cyan)' }}>
                  {t.count}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
