import React, { useMemo, useEffect, useState } from 'react';
import useThreatStore from '../../store/threatStore';
import { api } from '../../utils/api';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import './AIInsights.css';

const PROFILE_COLORS = {
  'Script Kiddie':           '#22c55e',
  'Automated Bot':           '#3b82f6',
  'Opportunistic Attacker':  '#fbbf24',
  'Advanced Persistent Threat': '#ef4444',
  'Insider Threat':          '#a855f7',
  'Researcher / Pen Tester': '#06b6d4',
};

const ATTACK_LABELS = [
  'SQL_INJECTION', 'XSS', 'BRUTE_FORCE', 'COMMAND_INJECTION',
  'DIRECTORY_TRAVERSAL', 'RECON', 'DATA_EXFILTRATION', 'PRIVILEGE_ESCALATION',
];

export default function AIInsights() {
  const { feedEvents, stats } = useThreatStore();
  const [dbAttackTypes, setDbAttackTypes] = useState({});
  const [deviceStats, setDeviceStats] = useState([]);

  useEffect(() => {
    const fetchTypes = () => {
      api.getAttackTypes().then(res => {
        setDbAttackTypes(res.attack_types || {});
      }).catch(console.error);

      api.getDeviceFootprints().then(res => {
        if (res.devices) {
            const arr = Object.entries(res.devices).map(([name, value]) => ({ name, value })).filter(d => d.value > 0);
            setDeviceStats(arr);
        }
      }).catch(console.error);
    };
    fetchTypes();
    const interval = setInterval(fetchTypes, 10000);
    return () => clearInterval(interval);
  }, []);

  const latestClassified = useMemo(() =>
    feedEvents.find((e) => e.attack_type && e.attack_type !== 'UNKNOWN'),
    [feedEvents]
  );

  const profileDist = useMemo(() => {
    const p = stats.attacker_profiles || {};
    const total = Object.values(p).reduce((a, b) => a + b, 0) || 1;
    return Object.entries(p)
      .map(([label, count]) => ({
        label, count,
        pct: Math.round((count / total) * 100),
        color: PROFILE_COLORS[label] || '#6b7280',
      }))
      .sort((a, b) => b.count - a.count);
  }, [stats.attacker_profiles]);

  const attackTypeDist = useMemo(() => {
    const counts = { ...dbAttackTypes };
    // Derive labels natively from the DB keys rather than just the fixed array to catch any new types
    const labels = new Set([...ATTACK_LABELS, ...Object.keys(counts).map(k => k.toUpperCase())]);
    
    let total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
    return Array.from(labels).map((t) => {
      const dbKey = Object.keys(counts).find(k => k.toUpperCase() === t) || t;
      return {
        type: t.replace(/_/g, ' '),
        count: counts[dbKey] || 0,
        pct: Math.round(((counts[dbKey] || 0) / total) * 100),
      };
    }).sort((a, b) => b.count - a.count);
  }, [dbAttackTypes]);

  return (
    <div className="ai-insights glass-card">
      <div className="ai-header">
        <span className="text-sm font-bold glow-cyan"> AI Analysis</span>
        <span className="dim text-xs mono">LIVE</span>
      </div>

      <div className="ai-body">
        {/* Latest classification */}
        {latestClassified && (
          <div className="ai-section">
            <div className="section-title mono text-xs dim">LATEST CLASSIFICATION</div>
            <div className="latest-card">
              <div className="latest-type" style={{ color: 'var(--cyan)' }}>
                {latestClassified.attack_type?.replace(/_/g, ' ')}
              </div>
              <div className="confidence-bar-wrapper">
                <div className="confidence-bar-track">
                  <div
                    className="confidence-bar-fill"
                    style={{ width: `${latestClassified.classification_confidence || 0}%` }}
                  />
                </div>
                <span className="mono text-xs" style={{ color: 'var(--cyan)' }}>
                  {latestClassified.classification_confidence?.toFixed(1)}%
                </span>
              </div>
              <div className="latest-meta dim text-xs mono">
                Anomaly: {latestClassified.anomaly_score?.toFixed(0)}% ·
                Profile: {latestClassified.attacker_profile}
              </div>
            </div>
          </div>
        )}

        {/* Attacker profiles */}
        {profileDist.length > 0 && (
          <div className="ai-section">
            <div className="section-title mono text-xs dim">ATTACKER PROFILES</div>
            <div className="profile-list">
              {profileDist.map((p) => (
                <div key={p.label} className="profile-row">
                  <span className="profile-dot" style={{ background: p.color }} />
                  <span className="text-xs" style={{ flex: 1, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {p.label}
                  </span>
                  <div className="profile-bar-track">
                    <div className="profile-bar-fill" style={{ width: `${p.pct}%`, background: p.color }} />
                  </div>
                  <span className="mono text-xs" style={{ color: p.color, width: 30, textAlign: 'right' }}>
                    {p.count}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Attack type bars */}
        <div className="ai-section">
          <div className="section-title mono text-xs dim">ATTACK TYPE HEATMAP</div>
          <div className="heatmap">
            {attackTypeDist.map((t) => {
              const isActive = t.pct > 0;
              const bgOpacity = Math.min(0.9, 0.1 + t.pct * 0.015);
              const isHighContrast = bgOpacity > 0.4;

              return (
              <div key={t.type} className="heatmap-cell"
                title={`${t.type}: ${t.count} events (${t.pct}%)`}
                style={{
                  background: isActive
                    ? `rgba(0,240,255,${bgOpacity})`
                    : 'var(--bg-elevated)',
                  borderColor: t.pct > 20 ? 'var(--cyan)' : 'inherit',
                }}
              >
                <div className="heatmap-label mono" style={{ 
                  fontSize: 9,
                  color: isHighContrast ? 'rgba(0,0,0,0.8)' : 'rgba(255,255,255,0.5)',
                  fontWeight: isHighContrast ? 800 : 500
                }}>
                  {t.type.slice(0, 6).toUpperCase()}
                </div>
                <div className="heatmap-count mono text-xs" style={{ 
                  color: isHighContrast ? '#000000' : 'var(--cyan)',
                  textShadow: isHighContrast ? 'none' : '0 0 10px rgba(0,240,255,0.3)'
                }}>
                  {t.count}
                </div>
              </div>
            )})}
          </div>
        </div>

        {/* Attacks Bar Chart */}
        {attackTypeDist.length > 0 && (
          <div className="ai-section">
             <div className="section-title mono text-xs dim" style={{ marginTop: 10 }}>ATTACK VOLUME DIAGRAM</div>
             <div style={{ width: '100%', height: 180 }}>
                 <ResponsiveContainer width="100%" height="100%">
                     <BarChart data={attackTypeDist} margin={{ top: 20, right: 30, left: -20, bottom: 5 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                        <XAxis dataKey="type" stroke="rgba(255,255,255,0.3)" fontSize={9} tickFormatter={(val) => val.slice(0, 6)} />
                        <YAxis stroke="rgba(255,255,255,0.3)" fontSize={10} allowDecimals={false} />
                        <Tooltip 
                            cursor={{ fill: 'rgba(0, 240, 255, 0.05)' }} 
                            contentStyle={{ backgroundColor: 'rgba(10, 15, 30, 0.9)', borderColor: 'rgba(0, 240, 255, 0.2)', color: '#fff', fontSize: '12px', fontFamily: 'monospace' }} 
                            itemStyle={{ color: 'var(--cyan)' }} 
                        />
                        <Bar dataKey="count" fill="url(#cyanGlow)" radius={[4, 4, 0, 0]} />
                        <defs>
                          <linearGradient id="cyanGlow" x1="0" y1="0" x2="0" y2="1">
                             <stop offset="0%" stopColor="#00f0ff" stopOpacity={0.8} />
                             <stop offset="100%" stopColor="#00f0ff" stopOpacity={0.1} />
                          </linearGradient>
                        </defs>
                     </BarChart>
                 </ResponsiveContainer>
             </div>
          </div>
        )}

        {/* Device Footprints */}
        {deviceStats.length > 0 && (
          <div className="ai-section">
            <div className="section-title mono text-xs dim" style={{ marginTop: 10 }}>DEVICE FOOTPRINTS</div>
            <div style={{ width: '100%', height: 200, marginTop: 10 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={deviceStats}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={5}
                    stroke="none"
                  >
                    {deviceStats.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={['#00f0ff', '#ef4444', '#f59e0b', '#8b5cf6', '#34d399'][index % 5]} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'rgba(10, 15, 30, 0.9)', borderColor: 'rgba(0, 240, 255, 0.2)', color: '#fff', fontSize: '12px', fontFamily: 'monospace' }}
                    itemStyle={{ color: 'var(--cyan)' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            {/* Legend underneath */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 12px', justifyContent: 'center', marginTop: -10 }}>
               {deviceStats.map((entry, idx) => (
                 <div key={entry.name} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10 }} className="mono text-muted">
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: ['#00f0ff', '#ef4444', '#f59e0b', '#8b5cf6', '#34d399'][idx % 5] }}></span>
                    <span style={{ color: 'var(--text-secondary)' }}>{entry.name} ({entry.value})</span>
                 </div>
               ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
