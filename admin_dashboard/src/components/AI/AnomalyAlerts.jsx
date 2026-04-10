import React from 'react';
import useThreatStore from '../../store/threatStore';
import './AnomalyAlerts.css';

export default function AnomalyAlerts() {
  const { anomalies, dismissAnomaly } = useThreatStore();
  if (anomalies.length === 0) return null;

  return (
    <div className="anomaly-bar">
      <span className="anomaly-bar-title mono text-xs">⚠ ANOMALIES</span>
      <div className="anomaly-list">
        {anomalies.slice(0, 5).map((a) => (
          <div key={a.id} className="anomaly-chip">
            <span className="pulse-dot pulse-dot-red" />
            <span className="anomaly-msg text-xs mono">{a.message}</span>
            <span className="anomaly-score mono text-xs" style={{ color: 'var(--threat-critical)' }}>
              {a.anomaly_score?.toFixed(0)}%
            </span>
            <button
              className="anomaly-dismiss"
              onClick={() => dismissAnomaly(a.id)}
              title="Dismiss"
            >✕</button>
          </div>
        ))}
      </div>
    </div>
  );
}
