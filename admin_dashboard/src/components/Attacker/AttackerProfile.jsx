import React, { useMemo, useState, useEffect } from 'react';
import { api } from '../../utils/api';
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
  if (!code || code === 'XX') return '';
  try {
    return String.fromCodePoint(
      ...[...code.toUpperCase()].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65)
    );
  } catch { return ''; }
}

export default function AttackerProfile({ onBack }) {
  const [attackers, setAttackers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedIp, setSelectedIp] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    if (!selectedIp) return;
    const selected = attackers.find(a => a.ip === selectedIp);
    const rawIp = selected ? selected.raw_ip : selectedIp;

    if (!window.confirm(`PERMANENT WIPEOUT - Are you sure you want to nuke all telemetry for ${selectedIp}?`)) return;
    
    setDeleting(true);
    try {
      await api.deleteAttacker(rawIp);
      setAttackers(prev => prev.filter(a => a.ip !== selectedIp));
      setSelectedIp(null);
    } catch (err) {
      console.error("Failed to delete attacker", err);
      alert("Wipe operation failed.");
    }
    setDeleting(false);
  };

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
          <span className="mono text-sm font-bold glow-cyan"> THREAT ACTORS</span>
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
            <div className="empty-icon"></div>
            <div className="empty-msg text-md">Select an attacker to profile</div>
            <div className="empty-sub dim text-sm">Click any hostile IP on the left</div>
          </div>
        ) : (
          <>
            {/* Header card */}
            <div className="profile-header glass-card">
              <div className="profile-main-info" style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div className="profile-ip mono text-2xl glow-cyan">{selected.ip}</div>
                  <button 
                    onClick={handleDelete}
                    disabled={deleting}
                    style={{ 
                      background: 'rgba(239, 68, 68, 0.1)', 
                      border: '1px solid rgba(239, 68, 68, 0.5)', 
                      color: '#fca5a5', 
                      padding: '4px 12px', 
                      borderRadius: '4px',
                      cursor: deleting ? 'wait' : 'pointer',
                      fontSize: '10px',
                      fontFamily: 'monospace',
                      boxShadow: '0 0 10px rgba(239, 68, 68, 0.2)'
                    }}
                  >
                    {deleting ? 'DATA NUKING...' : 'WIPE ATTACKER'}
                  </button>
                </div>
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

              {/* Behavior & Device Intel */}
              <div className="glass-card detail-box">
                <div className="detail-box-title mono text-xs dim">DEVICE & BEHAVIORAL FOOTPRINT</div>
                <InfoRow 
                  label="Network Route" 
                  value={selected.is_tor ? "ONION / TOR PROXY" : selected.is_vpn ? "SUSPECTED VPN" : "CLEARNET"} 
                  highlight={selected.is_vpn || selected.is_tor} 
                />
                <InfoRow 
                  label="JS Engine" 
                  value={selected.has_javascript ? "Executed (Emulated Browser)" : "Disabled (Headless CLI/Script)"} 
                  highlight={!selected.has_javascript} 
                />
                <InfoRow 
                  label="Mouse Telemetry" 
                  value={selected.mouse_moved ? "Cursor Activity Detected" : "Zero Movement"} 
                  highlight={!selected.mouse_moved} 
                />
                <InfoRow 
                  label="Avg Keystroke Inter." 
                  value={selected.avg_keystroke_ms ? `${selected.avg_keystroke_ms} ms` : "Instantaneous (Pasted)"} 
                />
                <InfoRow 
                  label="Avg Submit Delay" 
                  value={selected.avg_time_submit_s ? `${selected.avg_time_submit_s} s` : "N/A"} 
                />
                
                <div className="info-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 4, marginTop: 12 }}>
                  <span className="info-label dim text-xs mono">CAPTURED USER AGENTS</span>
                  {(selected.user_agents || []).length > 0 ? (
                    selected.user_agents.map((ua, i) => (
                      <div key={i} className="info-value text-xs mono" style={{ 
                        color: 'var(--cyan)', 
                        wordBreak: 'break-all',
                        background: 'rgba(0, 240, 255, 0.05)',
                        padding: '4px 6px',
                        borderLeft: '2px solid var(--cyan)',
                        marginTop: 4
                      }}>
                        {ua}
                      </div>
                    ))
                  ) : (
                    <span className="info-value text-xs dim">None Identified</span>
                  )}
                </div>
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
