import React, { useState } from 'react';
import useThreatStore from '../../store/threatStore';
import './Header.css';

export default function Header({ page }) {
  const { connected, anomalies, stats } = useThreatStore();
  const criticalCount = anomalies.filter((a) => a.anomaly_score > 70).length;

  const PAGE_TITLES = {
    dashboard: 'Command Center',
    attackers:  'Attacker Intelligence',
    ai:         'AI Insights',
    decoys:     'Decoy Lab',
  };

  return (
    <header className="header">
      {/* Left: breadcrumb */}
      <div className="header-left">
        <span className="header-icon">🛡️</span>
        <div>
          <div className="header-page-name">{PAGE_TITLES[page] || 'HoneyMind'}</div>
          <div className="header-sub mono text-xs dim">
            {stats.total_sessions || 0} total sessions · {stats.total_events || 0} events captured
          </div>
        </div>
      </div>

      {/* Center: alert ticker if anomalies */}
      {anomalies.length > 0 && (
        <div className="header-alerts">
          <span className="pulse-dot pulse-dot-red" />
          <span className="alert-text text-xs mono">
            {anomalies[0]?.message || `${anomalies.length} anomalies detected`}
          </span>
        </div>
      )}

      {/* Right: status chips */}
      <div className="header-right">
        {criticalCount > 0 && (
          <div className="chip chip-critical">
            ⚠ {criticalCount} CRITICAL
          </div>
        )}
        <div className={`chip ${connected ? 'chip-online' : 'chip-offline'}`}>
          <span className={`pulse-dot ${connected ? 'pulse-dot-cyan' : 'pulse-dot-red'}`} />
          {connected ? 'LIVE FEED' : 'RECONNECTING'}
        </div>
        <div className="header-time mono text-xs dim">
          {new Date().toLocaleTimeString('en-IN', { hour12: true, timeZone: 'Asia/Kolkata' })} IST
        </div>
      </div>
    </header>
  );
}
