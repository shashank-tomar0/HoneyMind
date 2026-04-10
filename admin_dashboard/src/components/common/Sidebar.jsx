import React from 'react';
import useThreatStore from '../../store/threatStore';
import './Sidebar.css';

const NAV = [
  { id: 'dashboard',  icon: '⬡', label: 'Command Center' },
  { id: 'attackers',  icon: '👁', label: 'Attackers' },
  { id: 'ai',         icon: '🧠', label: 'AI Insights' },
  { id: 'decoys',     icon: '🦎', label: 'Decoy Lab' },
];

export default function Sidebar({ active, onNav }) {
  const { connected, stats } = useThreatStore();

  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <span className="brand-icon">🍯</span>
        <div>
          <div className="brand-name shimmer">HoneyMind</div>
          <div className="brand-tagline">AI Threat Intelligence</div>
        </div>
      </div>

      {/* Connection status */}
      <div className="sidebar-status">
        <span className={`pulse-dot ${connected ? 'pulse-dot-cyan' : 'pulse-dot-red'}`} />
        <span className="status-text mono text-xs">
          {connected ? 'LIVE' : 'OFFLINE'}
        </span>
        {connected && (
          <span className="status-count mono text-xs">
            {stats.active_sessions || 0} active
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        {NAV.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${active === item.id ? 'nav-item--active' : ''}`}
            onClick={() => onNav(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
            {item.id === 'dashboard' && stats.active_sessions > 0 && (
              <span className="nav-badge">{stats.active_sessions}</span>
            )}
          </button>
        ))}
      </nav>

      {/* Threat level mini-summary */}
      <div className="sidebar-threats">
        <div className="threats-title dim text-xs mono">THREAT LEVELS</div>
        {[
          { key: 'CRITICAL', color: 'var(--threat-critical)' },
          { key: 'HIGH',     color: 'var(--threat-high)' },
          { key: 'MEDIUM',   color: 'var(--threat-medium)' },
          { key: 'LOW',      color: 'var(--threat-low)' },
        ].map(({ key, color }) => {
          const count = stats.threat_levels?.[key] || 0;
          const total = stats.total_sessions || 1;
          const pct = Math.round((count / total) * 100);
          return (
            <div key={key} className="threat-bar-row">
              <span className="threat-bar-label dim text-xs mono">{key}</span>
              <div className="threat-bar-track">
                <div
                  className="threat-bar-fill"
                  style={{ width: `${pct}%`, background: color }}
                />
              </div>
              <span className="threat-bar-count text-xs" style={{ color }}>{count}</span>
            </div>
          );
        })}
      </div>

      {/* Footer */}
      <div className="sidebar-footer dim text-xs mono">
        v1.0.0 · Hackathon Build
      </div>
    </aside>
  );
}
