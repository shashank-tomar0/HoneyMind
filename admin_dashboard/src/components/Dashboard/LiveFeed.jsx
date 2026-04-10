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
  return FLAG_MAP[code] || '🌐';
}

function formatTime(ts) {
  if (!ts) return '--:--:--';
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour12: false });
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

  // Auto-scroll to top on new events
  useEffect(() => {
    if (autoScroll && feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
  }, [feedEvents.length, autoScroll]);

  return (
    <div className="live-feed glass-card">
      <div className="feed-header">
        <div className="flex items-center gap-2">
          <span className="pulse-dot pulse-dot-cyan" />
          <span className="text-sm font-bold glow-cyan">LIVE FEED</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="dim text-xs mono">{feedEvents.length} events</span>
          <button
            className={`autoscroll-btn mono text-xs ${autoScroll ? 'active' : ''}`}
            onClick={() => setAutoScroll(!autoScroll)}
          >
            {autoScroll ? '⏸ PAUSE' : '▶ LIVE'}
          </button>
        </div>
      </div>

      <div className="feed-list" ref={feedRef}>
        {feedEvents.length === 0 && (
          <div className="feed-empty dim mono text-xs">
            Waiting for attack events...
          </div>
        )}
        {feedEvents.map((ev) => (
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
              {ev.is_anomaly && <span className="anomaly-tag">⚠ ANOMALY</span>}
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
                  {ev.real_ip && (
                    <DetailItem label="🪤 REAL IP EXPOSED" value={ev.real_ip} mono />
                  )}
                </div>
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
