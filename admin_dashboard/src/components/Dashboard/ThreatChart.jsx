import React, { useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import useThreatStore from '../../store/threatStore';
import './ThreatChart.css';

const ATTACK_COLORS = {
  SQL_INJECTION:         '#ef4444',
  XSS:                   '#f97316',
  DIRECTORY_TRAVERSAL:   '#fbbf24',
  BRUTE_FORCE:           '#a855f7',
  COMMAND_INJECTION:     '#ff006e',
  RECON:                 '#3b82f6',
  DATA_EXFILTRATION:     '#06b6d4',
  PRIVILEGE_ESCALATION:  '#22c55e',
  NORMAL:                '#475569',
  UNKNOWN:               '#374151',
};

export default function ThreatChart() {
  const { feedEvents, stats } = useThreatStore();

  // Compute attack type distribution from feed
  const typeData = useMemo(() => {
    const counts = {};
    feedEvents.forEach((ev) => {
      const t = ev.attack_type || 'UNKNOWN';
      counts[t] = (counts[t] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value, color: ATTACK_COLORS[name] || '#475569' }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  }, [feedEvents]);

  // Country distribution
  const countryData = useMemo(() => {
    return (stats.top_countries || []).slice(0, 6).map(([country, count]) => ({
      country: country.length > 12 ? country.slice(0, 12) + '…' : country,
      count,
    }));
  }, [stats.top_countries]);

  const customTooltip = ({ active, payload }) => {
    if (active && payload?.length) {
      return (
        <div style={{
          background: 'var(--bg-elevated)', border: '1px solid var(--border)',
          borderRadius: 8, padding: '8px 12px', fontSize: 12,
          fontFamily: 'var(--font-mono)'
        }}>
          <div style={{ color: payload[0].payload.color || 'var(--cyan)' }}>{payload[0].name}</div>
          <div style={{ color: 'var(--text-primary)', fontWeight: 700 }}>{payload[0].value} events</div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="threat-chart glass-card">
      <div className="chart-header">
        <span className="text-sm font-bold">Attack Distribution</span>
        <span className="dim text-xs mono">{feedEvents.length} events</span>
      </div>

      <div className="chart-body">
        {/* Donut chart */}
        <div className="donut-section">
          {typeData.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie
                  data={typeData}
                  cx="50%" cy="50%"
                  innerRadius={45} outerRadius={70}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {typeData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} stroke="transparent" />
                  ))}
                </Pie>
                <Tooltip content={customTooltip} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="chart-empty dim mono text-xs">No data yet…</div>
          )}

          {/* Legend */}
          <div className="donut-legend">
            {typeData.slice(0, 5).map((d) => (
              <div key={d.name} className="legend-row">
                <span className="legend-dot" style={{ background: d.color }} />
                <span className="mono text-xs" style={{ color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {d.name.replace(/_/g, ' ')}
                </span>
                <span className="mono text-xs" style={{ color: d.color }}>{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Country bar chart */}
        {countryData.length > 0 && (
          <div className="bar-section">
            <div className="dim text-xs mono" style={{ marginBottom: 6, letterSpacing: 0.5 }}>TOP SOURCE COUNTRIES</div>
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={countryData} layout="vertical" margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="country" width={75}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                  axisLine={false} tickLine={false}
                />
                <Bar dataKey="count" fill="var(--cyan)" radius={[0, 3, 3, 0]} barSize={10}>
                  {countryData.map((_, i) => (
                    <Cell key={i} fill={`hsla(${190 + i * 12}, 90%, 60%, 0.8)`} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}
