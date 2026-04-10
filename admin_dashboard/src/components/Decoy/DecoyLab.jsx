import React, { useState, useEffect } from 'react';
import { BACKEND } from '../../utils/api'; // Make sure this is defined, or just use the local address.

const BACKEND_URL = "http://localhost:5000";

export default function DecoyLab() {
  const DECOY_TYPES = [
    { id: 'network_logs', icon: '📡', name: 'Network Logs', type: 'Fake live access logs', color: 'var(--cyan)' },
    { id: 'telemetry', icon: '📊', name: 'System Telemetry', type: 'Dashboard stats', color: 'var(--magenta)' },
    { id: 'db_dump', icon: '🗄️', name: 'Employee DB', type: 'Data leak records', color: 'var(--amber)' },
    { id: 'config', icon: '⚙️', name: 'config.json', type: 'App Config + API Keys', color: 'var(--purple)' },
  ];

  const [decoys, setDecoys] = useState({});
  const [loadingType, setLoadingType] = useState(null);

  useEffect(() => {
    fetchDecoys();
  }, []);

  const fetchDecoys = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/decoy/list`);
      const data = await res.json();
      setDecoys(data);
    } catch (err) {
      console.error("Failed to fetch decoys:", err);
    }
  };

  const handleGenerate = async (typeId) => {
    setLoadingType(typeId);
    try {
      const res = await fetch(`${BACKEND_URL}/api/decoy/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: typeId })
      });
      const data = await res.json();
      if (data.status === 'success') {
        const generated = data.data.content;
        setDecoys(prev => ({ ...prev, [typeId]: generated }));
      } else {
        alert('Generation failed: ' + data.error);
      }
    } catch (err) {
      console.error("Failed to generate decoy:", err);
      alert('Network error while generating decoy.');
    }
    setLoadingType(null);
  };

  return (
    <div style={{ padding: '2rem', height: '100%', overflow: 'auto' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h1 className="text-2xl font-bold" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span>🦎</span> AI Decoy Lab
        </h1>
        <p className="dim text-sm" style={{ marginTop: '0.5rem', maxWidth: 600, lineHeight: 1.5 }}>
          Generate hyper-realistic fake data using <strong style={{ color: 'var(--cyan)' }}>GLM-5</strong> via Featherless AI. 
          The data created here is immediately fed into the honeypot endpoints and bait files to deceive attackers.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1.5rem' }}>
        {DECOY_TYPES.map((d) => (
          <div key={d.id} className="glass-card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
              <div style={{ fontSize: '2rem', background: 'var(--bg-elevated)', padding: '0.5rem', borderRadius: 8 }}>{d.icon}</div>
              <div>
                <div className="mono font-bold text-lg" style={{ color: d.color }}>{d.name}</div>
                <div className="dim text-sm">{d.type}</div>
              </div>
            </div>

            <div style={{ flex: 1, marginBottom: '1rem', background: '#111', padding: '1rem', borderRadius: 8, overflow: 'auto', maxHeight: 200 }}>
              {decoys[d.id] ? (
                <pre className="mono text-xs dim" style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {JSON.stringify(decoys[d.id], null, 2)}
                </pre>
              ) : (
                <div className="mono text-xs dim" style={{ textAlign: 'center', marginTop: '2rem' }}>
                  No AI data generated yet.
                </div>
              )}
            </div>

            <button
              onClick={() => handleGenerate(d.id)}
              disabled={loadingType === d.id}
              style={{
                width: '100%',
                padding: '0.75rem',
                background: loadingType === d.id ? 'var(--bg-elevated)' : d.color,
                color: loadingType === d.id ? 'var(--text-muted)' : '#000',
                border: 'none',
                borderRadius: 6,
                fontWeight: 'bold',
                cursor: loadingType === d.id ? 'not-allowed' : 'pointer',
                transition: 'opacity 0.2s',
              }}
              onMouseOver={(e) => { if (loadingType !== d.id) e.target.style.opacity = 0.8; }}
              onMouseOut={(e) => { e.target.style.opacity = 1; }}
            >
              {loadingType === d.id ? 'Generating via GLM-5... 🧠' : 'Generate Decoy'}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
