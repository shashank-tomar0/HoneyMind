import React, { useMemo } from 'react';
import useThreatStore from '../../store/threatStore';
import './AttackerProfile.css';

const LEVEL_CLASS = {
  LOW: 'badge-low', MEDIUM: 'badge-medium',
  HIGH: 'badge-high', CRITICAL: 'badge-critical',
};

function formatTime(ts) {
  if (!ts) return '–';
  return new Date(ts).toLocaleString();
}

export default function AttackerProfile({ onBack }) {
  const { selectedSessionId, activeSessions, feedEvents } = useThreatStore();
  const session = activeSessions[selectedSessionId];
  const events = useMemo(() =>
    feedEvents.filter((e) => e.session_id === selectedSessionId).slice(0, 50),
    [feedEvents, selectedSessionId]
  );

  if (!selectedSessionId || !session) {
    return (
      <div className="attacker-empty glass-card">
        <div className="empty-icon">👁</div>
        <div className="empty-msg text-md">Select an attacker to profile</div>
        <div className="empty-sub dim text-sm">Click any event in the live feed or globe arc</div>
      </div>
    );
  }

  const duration = session.start_time
    ? Math.round((Date.now() - new Date(session.start_time)) / 1000)
    : 0;

  return (
    <div className="attacker-profile">
      {/* Header */}
      <div className="profile-header glass-card">
        <button className="btn btn-cyan" onClick={onBack}>← Back</button>
        <div className="profile-main-info">
          <div className="profile-ip mono text-2xl glow-cyan">
            {session.attacker_ip?.replace('sim_', '') || '?.?.?.?'}
          </div>
          <div className="profile-meta">
            <span>{session.city}, {session.country}</span>
            <span className="dim">·</span>
            <span className="mono text-xs">{session.isp}</span>
            <span className="dim">·</span>
            <span className={`badge ${LEVEL_CLASS[session.threat_level]}`}>{session.threat_level}</span>
          </div>
        </div>
        <div className="profile-score">
          <div className="score-ring" style={{ '--score': session.threat_score }}>
            <div className="score-value mono">{session.threat_score?.toFixed(0)}</div>
            <div className="score-label dim text-xs">THREAT</div>
          </div>
        </div>
      </div>

      {/* Details grid */}
      <div className="profile-grid">
        <div className="glass-card detail-box">
          <div className="detail-box-title mono text-xs dim">SESSION INFO</div>
          <InfoRow label="Vector" value={session.attack_vector} />
          <InfoRow label="Profile" value={session.attacker_profile} highlight />
          <InfoRow label="Events" value={session.total_events} />
          <InfoRow label="Commands" value={session.command_count} />
          <InfoRow label="Duration" value={`${duration}s`} />
          <InfoRow label="Started" value={formatTime(session.start_time)} />
          <InfoRow label="Status" value={session.is_active ? '🔴 ACTIVE' : '✅ ENDED'} />
        </div>

        <div className="glass-card detail-box">
          <div className="detail-box-title mono text-xs dim">GEOGRAPHIC INTEL</div>
          <InfoRow label="Country" value={`${session.country} (${session.country_code})`} />
          <InfoRow label="City" value={session.city} />
          <InfoRow label="ISP" value={session.isp} />
          <InfoRow label="Latitude" value={session.latitude?.toFixed(4)} />
          <InfoRow label="Longitude" value={session.longitude?.toFixed(4)} />
        </div>

        <div className="glass-card detail-box">
          <div className="detail-box-title mono text-xs dim">AI ASSESSMENT</div>
          <InfoRow label="Profile Type" value={session.attacker_profile} highlight />
          <InfoRow label="Threat Score" value={`${session.threat_score?.toFixed(1)} / 100`} />
          <InfoRow label="Threat Level" value={session.threat_level} />
        </div>
      </div>

      {/* Session replay */}
      <div className="glass-card session-replay">
        <div className="replay-header">
          <span className="mono text-sm font-bold glow-lime">$ COMMAND HISTORY</span>
          <span className="dim text-xs mono">{events.length} events</span>
        </div>
        <div className="terminal">
          {events.length === 0 && (
            <div className="dim mono text-xs" style={{ padding: '10px' }}>No events logged yet…</div>
          )}
          {events.map((ev, i) => (
            <div key={ev.id || i} className="terminal-line">
              <span className="terminal-prompt glow-lime">root@honeymind:~$</span>
              <span className={`terminal-cmd mono text-xs ${ev.is_anomaly ? 'anomaly-cmd' : ''}`}>
                {ev.payload || '(empty)'}
              </span>
              <span className={`badge ${LEVEL_CLASS[ev.threat_level]} terminal-badge`}>
                {ev.attack_type?.replace(/_/g, ' ') || ev.event_type}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value, highlight }) {
  return (
    <div className="info-row">
      <span className="info-label dim text-xs mono">{label}</span>
      <span className={`info-value text-xs ${highlight ? 'glow-cyan' : ''}`}>{value || '–'}</span>
    </div>
  );
}
