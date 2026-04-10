import React, { useMemo, useState, useEffect } from 'react';
import './AttackerProfile.css';

const BACKEND = 'http://localhost:5000';

const LEVEL_CLASS = {
  ATTACKER: 'badge-critical', SUSPICIOUS: 'badge-high',
  HIGH: 'badge-high', CRITICAL: 'badge-critical', MEDIUM: 'badge-medium',
};

function formatTime(ts) {
  if (!ts) return '–';
  const raw = String(ts);
  const d = new Date(raw.endsWith('Z') || raw.includes('+') ? raw : raw + 'Z');
  return d.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
}

function relativeTime(ts) {
  if (!ts) return '–';
  const raw = String(ts);
  const d = new Date(raw.endsWith('Z') || raw.includes('+') ? raw : raw + 'Z');
  const diff = Math.round((Date.now() - d) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  return `${Math.round(diff / 3600)}h ago`;
}

function getFlag(code) {
  if (!code || code === 'XX') return '🏴';
  try {
    return String.fromCodePoint(
      ...[...code.toUpperCase()].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65)
    );
  } catch { return '🏴'; }
}

export default function AttackerProfile({ onBack }) {
  const [attackers, setAttackers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedIp, setSelectedIp] = useState(null);

  // Fetch attackers from DB — auto-refresh every 5s
  useEffect(() => {
    const fetchAttackers = () => {
      fetch(`${BACKEND}/api/dashboard/attackers`)
        .then((r) => r.json())
        .then((data) => {
          setAttackers(data.attackers || []);
          setLoading(false);
        })
        .catch((err) => {
          console.error('Failed to fetch attackers:', err);
          setLoading(false);
        });
    };
    fetchAttackers();
    const interval = setInterval(fetchAttackers, 5000);
    return () => clearInterval(interval);
  }, []);

  const selected = selectedIp ? attackers.find((a) => a.ip === selectedIp) : null;

  return (
    <div className="attacker-page">
      {/* Left: Attacker list */}
      <div className="attacker-list glass-card">
        <div className="list-header">
          <span className="mono text-sm font-bold glow-cyan">⚡ THREAT ACTORS</span>
          <span className="dim text-xs mono">{attackers.length} hostile</span>
        </div>

        {loading && (
          <div className="dim mono text-xs" style={{ padding: 16, textAlign: 'center' }}>
            Loading from database...
          </div>
        )}

        {!loading && attackers.length === 0 && (
          <div className="dim mono text-xs" style={{ padding: 16, textAlign: 'center' }}>
            No hostile actors detected yet.<br />
            Attack the honeypot to populate.
          </div>
        )}

        {attackers.map((atk) => (
          <div
            key={atk.ip}
            className={`attacker-row ${selectedIp === atk.ip ? 'attacker-row--active' : ''}`}
            onClick={() => setSelectedIp(atk.ip)}
          >
            <div className="attacker-row-top">
              <span className="mono text-xs" style={{ color: 'var(--cyan)' }}>{atk.ip}</span>
              <span className={`badge ${LEVEL_CLASS[atk.threat_level]}`}>{atk.threat_level}</span>
            </div>
            <div className="attacker-row-bottom">
              <span className="dim text-xs">{getFlag(atk.country_code)} {atk.city}, {atk.country}</span>
              <span className="dim text-xs mono">{atk.session_count} sessions</span>
            </div>
            <div className="attacker-row-tags">
              {(atk.attack_types || []).map((t) => (
                <span key={t} className="atk-tag mono text-xs">{t.replace(/_/g, ' ')}</span>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Right: Detail panel */}
      <div className="attacker-detail">
        {!selected ? (
          <div className="attacker-empty glass-card">
            <div className="empty-icon">👁</div>
            <div className="empty-msg text-md">Select an attacker to profile</div>
            <div className="empty-sub dim text-sm">Click any hostile IP on the left</div>
          </div>
        ) : (
          <>
            {/* Header card */}
            <div className="profile-header glass-card">
              <div className="profile-main-info">
                <div className="profile-ip mono text-2xl glow-cyan">{selected.ip}</div>
                <div className="profile-meta">
                  <span>{getFlag(selected.country_code)} {selected.city}, {selected.country}</span>
                  <span className="dim">·</span>
                  <span className={`badge ${LEVEL_CLASS[selected.threat_level]}`}>{selected.threat_level}</span>
                  <span className="dim">·</span>
                  <span className="mono text-xs dim">{selected.session_count} sessions</span>
                </div>
              </div>
              <div className="profile-score">
                <div className="score-ring" style={{ '--score': selected.threat_score }}>
                  <div className="score-value mono">{selected.threat_score}</div>
                  <div className="score-label dim text-xs">THREAT</div>
                </div>
              </div>
            </div>

            {/* Detail grid */}
            <div className="profile-grid">
              <div className="glass-card detail-box">
                <div className="detail-box-title mono text-xs dim">SESSION INFO</div>
                <InfoRow label="First Seen" value={formatTime(selected.first_seen)} />
                <InfoRow label="Last Seen" value={relativeTime(selected.last_seen)} />
                <InfoRow label="Sessions" value={selected.session_count} />
                <InfoRow label="Events" value={selected.event_count} />
                <InfoRow label="Credentials Tried" value={selected.credential_count} />
                <InfoRow label="Attack Types" value={(selected.attack_types || []).join(', ')} />
                <InfoRow label="Threat Score" value={`${selected.threat_score} / 100`} />
              </div>

              <div className="glass-card detail-box">
                <div className="detail-box-title mono text-xs dim">GEOGRAPHIC INTEL</div>
                <InfoRow label="Country" value={`${selected.country} (${selected.country_code})`} />
                <InfoRow label="City" value={selected.city} />
                <InfoRow label="ISP" value={selected.isp || '–'} />
                <InfoRow label="Organization" value={selected.org || '–'} />
                <InfoRow label="Latitude" value={selected.lat?.toFixed(4)} />
                <InfoRow label="Longitude" value={selected.lng?.toFixed(4)} />
              </div>

              {/* Canary section */}
              {selected.canary_hits && selected.canary_hits.length > 0 && (
                <div className="glass-card detail-box" style={{
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  background: 'rgba(239, 68, 68, 0.05)',
                }}>
                  <div className="detail-box-title mono text-xs" style={{ color: '#f87171' }}>
                    🪤 CANARY TOKEN INTEL ({selected.canary_hits.length} hits)
                  </div>
                  {selected.canary_hits.map((ch, i) => (
                    <div key={i} style={{
                      padding: '8px 0',
                      borderBottom: i < selected.canary_hits.length - 1
                        ? '1px solid rgba(255,255,255,0.04)' : 'none',
                    }}>
                      <InfoRow label="Real IP" value={ch.real_ip} highlight />
                      <InfoRow label="Location" value={`${ch.city}, ${ch.country}`} />
                      <InfoRow label="ISP" value={ch.isp || '–'} />
                      <InfoRow label="Bait File" value={ch.file} />
                      <InfoRow label="Triggered" value={formatTime(ch.timestamp)} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
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
