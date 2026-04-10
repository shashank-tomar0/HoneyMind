import React, { useMemo } from 'react';
import useThreatStore from '../../store/threatStore';
import './StatsPanel.css';

const CARD_DEFS = [
  {
    id: 'total',
    icon: '🎯',
    label: 'Total Attacks',
    getValue: (s) => s.total_sessions || 0,
    color: 'var(--cyan)',
    format: (v) => v.toLocaleString(),
  },
  {
    id: 'active',
    icon: '🔴',
    label: 'Active Sessions',
    getValue: (s) => s.active_sessions || 0,
    color: 'var(--magenta)',
    format: (v) => v,
    pulse: true,
  },
  {
    id: 'score',
    icon: '⚡',
    label: 'Avg Threat Score',
    getValue: (s) => s.avg_threat_score || 0,
    color: 'var(--amber)',
    format: (v) => `${v.toFixed(1)}`,
    suffix: '/100',
  },
  {
    id: 'events',
    icon: '📡',
    label: 'Events Captured',
    getValue: (s) => s.total_events || 0,
    color: 'var(--purple)',
    format: (v) => v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v,
  },
];

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
    <div className="stats-panel">
      {CARD_DEFS.map((card) => {
        const value = card.getValue(stats);
        return (
          <div key={card.id} className="stat-card glass-card" style={{ '--card-color': card.color }}>
            <div className="stat-icon">{card.icon}</div>
            <div className="stat-body">
              <div className="stat-value" style={{ color: card.color }}>
                {card.format(value)}
                {card.suffix && <span className="stat-suffix">{card.suffix}</span>}
                {card.pulse && value > 0 && (
                  <span className="pulse-dot pulse-dot-red" style={{ marginLeft: 6 }} />
                )}
              </div>
              <div className="stat-label dim text-xs">{card.label}</div>
            </div>
          </div>
        );
      })}

      {/* Attack vector mini-card */}
      <div className="stat-card stat-card--mini glass-card">
        <div className="mini-row">
          <span className="dim text-xs mono">TOP VECTOR</span>
          <span className="mono text-sm" style={{ color: 'var(--cyan)' }}>{topVector}</span>
        </div>
        <div className="mini-row">
          <span className="dim text-xs mono">TOP PROFILE</span>
          <span className="mono text-xs" style={{ color: 'var(--magenta)' }}>{topProfile}</span>
        </div>
      </div>
    </div>
  );
}
