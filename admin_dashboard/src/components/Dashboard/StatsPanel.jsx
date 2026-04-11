import React, { useMemo } from 'react';
import useThreatStore from '../../store/threatStore';
import './StatsPanel.css';

export default function StatsPanel() {
  const { stats } = useThreatStore();

  const topVector = useMemo(() => {
    const v = stats.attack_vectors || {};
    return Object.entries(v).sort((a, b) => b[1] - a[1])[0]?.[0] || '—';
  }, [stats.attack_vectors]);

  const topProfile = useMemo(() => {
    const p = stats.attacker_profiles || {};
    return Object.entries(p).sort((a, b) => b[1] - a[1])[0]?.[0] || '—';
  }, [stats.attacker_profiles]);

  return (
    <div className="stats-unified-card glass-card">
      <div className="stat-segment" style={{ '--accent': 'var(--cyan)' }}>
        <div className="stat-val-container">
          <span className="stat-val">{stats.total_sessions?.toLocaleString() || 0}</span>
        </div>
        <span className="stat-title">TOTAL ATTACKS</span>
      </div>

      <div className="stat-divider" />

      <div className="stat-segment" style={{ '--accent': 'var(--magenta)' }}>
        <div className="stat-val-container">
          <span className="stat-val">{stats.active_sessions || 0}</span>
          {(stats.active_sessions > 0) && <span className="pulse-dot pulse-dot-red" style={{ marginLeft: 8 }} />}
        </div>
        <span className="stat-title">ACTIVE SESSIONS</span>
      </div>

      <div className="stat-divider" />

      <div className="stat-segment" style={{ '--accent': 'var(--amber)' }}>
        <div className="stat-val-container">
          <span className="stat-val">{(stats.avg_threat_score || 0).toFixed(1)}</span>
          <span className="stat-suffix">/100</span>
        </div>
        <span className="stat-title">AVG THREAT SCORE</span>
      </div>

      <div className="stat-divider" />

      <div className="stat-segment" style={{ '--accent': 'var(--purple)' }}>
        <div className="stat-val-container">
          <span className="stat-val">
            {(stats.total_events || 0) >= 1000 
              ? `${((stats.total_events || 0) / 1000).toFixed(1)}k` 
              : (stats.total_events || 0)}
          </span>
        </div>
        <span className="stat-title">EVENTS CAPTURED</span>
      </div>

      <div className="stat-divider" />

      <div className="stat-segment-meta" style={{ '--accent': 'var(--text-primary)' }}>
        <div className="meta-row">
          <span className="meta-label">TOP VECTOR</span>
          <span className="meta-val" style={{ color: 'var(--cyan)' }}>{topVector}</span>
        </div>
        <div className="meta-row">
          <span className="meta-label">TOP PROFILE</span>
          <span className="meta-val" style={{ color: 'var(--magenta)' }}>{topProfile}</span>
        </div>
      </div>
    </div>
  );
}
