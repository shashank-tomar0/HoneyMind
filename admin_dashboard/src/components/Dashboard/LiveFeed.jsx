import React, { useRef, useEffect, useState } from 'react';
import useThreatStore from '../../store/threatStore';
import './LiveFeed.css';

const FLAG_MAP = {
  CN: '🇨🇳', RU: '🇷🇺', US: '🇺🇸', KR: '🇰🇷', IN: '🇮🇳', DE: '🇩🇪',
  BR: '🇧🇷', JP: '🇯🇵', FR: '🇫🇷', AU: '🇦🇺', AE: '🇦🇪', TR: '🇹🇷',
  UA: '🇺🇦', MX: '🇲🇽', SG: '🇸🇬', EG: '🇪🇬', ZA: '🇿🇦', CA: '🇨🇦',
  GB: '🇬🇧', GR: '🇬🇷',
};

function getFlag(code) {
  return FLAG_MAP[code] || '';
}

function formatTime(ts) {
  if (!ts) return '--:--:--';
  const raw = String(ts);
  // Ensure UTC timestamps get parsed correctly
  const d = new Date(raw.endsWith('Z') || raw.includes('+') ? raw : raw + 'Z');
  return d.toLocaleTimeString('en-IN', { hour12: false, timeZone: 'Asia/Kolkata' });
}

const LEVEL_CLASS = {
  LOW: 'badge-low', MEDIUM: 'badge-medium',
  HIGH: 'badge-high', CRITICAL: 'badge-critical',
};

export default function LiveFeed({ onSelectSession }) {
  const { feedEvents } = useThreatStore();
  const feedRef = useRef(null);
  const [expanded, setExpanded] = useState(null);
  const [autoScroll, setAutoScroll] = useState(true);

  const filteredEvents = feedEvents.filter(ev => 
    ev.attack_type !== 'CREDENTIAL_ATTACK' && ev.threat_level !== 'LOW'
  );

  // Auto-scroll to top on new events
  useEffect(() => {
    if (autoScroll && feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
  }, [filteredEvents.length, autoScroll]);

  return (
    <div className="live-feed glass-card">
      <div className="feed-header">
        <div className="flex items-center gap-2">
          <span className="pulse-dot pulse-dot-cyan" />
          <span className="text-sm font-bold glow-cyan">LIVE FEED</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="dim text-xs mono">{filteredEvents.length} events</span>
          <button
            className={`autoscroll-btn mono text-xs ${autoScroll ? 'active' : ''}`}
            onClick={() => setAutoScroll(!autoScroll)}
          >
            {autoScroll ? '⏸ PAUSE' : '▶ LIVE'}
          </button>
        </div>
      </div>

      <div className="feed-list" ref={feedRef}>
        {filteredEvents.length === 0 && (
          <div className="feed-empty dim mono text-xs">
            Waiting for attack events...
          </div>
        )}
        {filteredEvents.map((ev) => (
          <div
            key={ev.id}
            className={`feed-row ${expanded === ev.id ? 'feed-row--expanded' : ''} ${ev.is_anomaly ? 'feed-row--anomaly' : ''}`}
            onClick={() => setExpanded(expanded === ev.id ? null : ev.id)}
          >
            <div className="feed-row-main">
              <span className="feed-time mono text-xs dim">{formatTime(ev.timestamp)}</span>
              <span className="feed-flag">{getFlag(ev.country_code)}</span>
              <span className="feed-ip mono text-xs" style={{ color: 'var(--cyan)' }}>
                {ev.attacker_ip?.replace('sim_', '') || '?.?.?.?'}
              </span>
              <span className={`badge ${LEVEL_CLASS[ev.threat_level] || 'badge-low'}`}>
                {ev.threat_level}
              </span>
              <span className="feed-type mono text-xs" style={{ color: 'var(--text-secondary)' }}>
                {ev.attack_type || 'UNKNOWN'}
              </span>
              {ev.is_anomaly && <span className="anomaly-tag"> ANOMALY</span>}
              <span className="feed-score mono text-xs" style={{ color: scoreColor(ev.threat_score) }}>
                {ev.threat_score?.toFixed(0) || 0}
              </span>
            </div>

            {expanded === ev.id && (
              <div className="feed-row-detail">
                <div className="detail-grid">
                  <DetailItem label="PAYLOAD" value={ev.payload} mono />
                  <DetailItem label="VECTOR" value={ev.attack_vector} />
                  <DetailItem label="PROFILE" value={ev.attacker_profile} />
                  <DetailItem label="CONFIDENCE" value={`${ev.classification_confidence}%`} />
                  <DetailItem label="ANOMALY SCORE" value={`${ev.anomaly_score}%`} />
                  <DetailItem label="LOCATION" value={`${ev.city}, ${ev.country}`} />
                </div>

                {/* ── Canary: Dual IP Comparison Card ── */}
                {ev.real_ip_geo && (
                  <div style={{
                    marginTop: 10,
                    padding: '14px',
                    background: 'rgba(239, 68, 68, 0.08)',
                    border: '1px solid rgba(239, 68, 68, 0.35)',
                    borderRadius: 8,
                  }}>
                    <div className="mono text-xs" style={{ color: '#f87171', fontWeight: 700, marginBottom: 10 }}>
                      🪤 CANARY TOKEN — IP COMPARISON
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                      {/* LEFT: Original Attack IP */}
                      <div style={{
                        padding: '10px 12px',
                        background: 'rgba(59, 130, 246, 0.1)',
                        border: '1px solid rgba(59, 130, 246, 0.3)',
                        borderRadius: 6,
                      }}>
                        <div className="mono text-xs" style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 6 }}>
                           HONEYPOT LOGIN IP
                        </div>
                        {ev.original_ip_geo ? (
                          <>
                            <DetailItem label="IP" value={ev.original_ip_geo.ip} mono />
                            <DetailItem label="LOCATION" value={`${ev.original_ip_geo.city}, ${ev.original_ip_geo.country}`} />
                            <DetailItem label="ISP" value={ev.original_ip_geo.isp} />
                            <DetailItem label="COORDS" value={`${ev.original_ip_geo.lat?.toFixed(4)}, ${ev.original_ip_geo.lng?.toFixed(4)}`} mono />
                          </>
                        ) : (
                          <div className="dim text-xs">No session linked</div>
                        )}
                      </div>

                      {/* RIGHT: Canary Revealed IP */}
                      <div style={{
                        padding: '10px 12px',
                        background: 'rgba(239, 68, 68, 0.1)',
                        border: '1px solid rgba(239, 68, 68, 0.3)',
                        borderRadius: 6,
                      }}>
                        <div className="mono text-xs" style={{ color: '#f87171', fontWeight: 700, marginBottom: 6 }}>
                          🪤 CANARY REVEALED IP
                        </div>
                        <DetailItem label="IP" value={ev.real_ip_geo.ip} mono />
                        <DetailItem label="LOCATION" value={`${ev.real_ip_geo.city}, ${ev.real_ip_geo.country}`} />
                        <DetailItem label="ISP" value={ev.real_ip_geo.isp} />
                        <DetailItem label="COORDS" value={`${ev.real_ip_geo.lat?.toFixed(4)}, ${ev.real_ip_geo.lng?.toFixed(4)}`} mono />
                      </div>
                    </div>

                    {/* Match indicator */}
                    <div className="mono text-xs" style={{
                      marginTop: 8,
                      padding: '6px 10px',
                      background: ev.original_ip === ev.real_ip
                        ? 'rgba(52, 211, 153, 0.1)' : 'rgba(245, 158, 11, 0.1)',
                      border: `1px solid ${ev.original_ip === ev.real_ip
                        ? 'rgba(52, 211, 153, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
                      borderRadius: 4,
                      color: ev.original_ip === ev.real_ip ? '#34d399' : '#fbbf24',
                      textAlign: 'center',
                    }}>
                      {ev.original_ip === ev.real_ip
                        ? ' IPs MATCH — Same network origin confirmed'
                        : ' IPs DIFFER — Attacker may be using VPN/proxy at login'}
                    </div>
                  </div>
                )}

                <button className="btn btn-cyan" style={{ marginTop: 8, fontSize: 11 }}
                  onClick={(e) => { e.stopPropagation(); onSelectSession?.(ev.session_id); }}>
                  View Session →
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function DetailItem({ label, value, mono }) {
  return (
    <div className="detail-item">
      <div className="detail-label dim text-xs mono">{label}</div>
      <div className={`detail-value text-xs ${mono ? 'mono' : ''}`} style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>
        {value || '—'}
      </div>
    </div>
  );
}

function scoreColor(score) {
  if (score >= 80) return 'var(--threat-critical)';
  if (score >= 60) return 'var(--threat-high)';
  if (score >= 35) return 'var(--threat-medium)';
  return 'var(--threat-low)';
}
