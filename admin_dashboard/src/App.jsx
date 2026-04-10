import React, { useEffect, useState } from 'react';
import './index.css';
import Sidebar from './components/common/Sidebar';
import Header from './components/common/Header';
import CommandCenter from './components/Dashboard/CommandCenter';
import AttackerProfile from './components/Attacker/AttackerProfile';
import AIInsights from './components/AI/AIInsights';
import { connectSocket } from './utils/socket';
import useThreatStore from './store/threatStore';

function App() {
  const [page, setPage] = useState('dashboard');
  const { setSelectedSession } = useThreatStore();

  // Connect WebSocket on mount (cleanup prevents StrictMode duplicates)
  useEffect(() => {
    const sock = connectSocket();
    return () => {
      if (sock) sock.disconnect();
    };
  }, []);

  const handleSelectSession = (sessionId) => {
    setSelectedSession(sessionId);
    setPage('attackers');
  };

  const handleNav = (id) => setPage(id);

  const renderPage = () => {
    switch (page) {
      case 'dashboard':
        return <CommandCenter onSelectSession={handleSelectSession} />;
      case 'attackers':
        return <AttackerProfile onBack={() => setPage('dashboard')} />;
      case 'ai':
        return (
          <div style={{ padding: 10, height: '100%', overflow: 'auto' }}>
            <AIInsights />
          </div>
        );
      case 'decoys':
        return <DecoyLab />;
      default:
        return <CommandCenter onSelectSession={handleSelectSession} />;
    }
  };

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <Sidebar active={page} onNav={handleNav} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        <Header page={page} />
        <div style={{ flex: 1, overflow: 'hidden' }}>
          {renderPage()}
        </div>
      </div>
    </div>
  );
}

// Simple Decoy Lab placeholder
function DecoyLab() {
  const DECOY_TYPES = [
    { icon: '📄', name: '/etc/passwd', type: 'Linux Password File', color: 'var(--cyan)' },
    { icon: '🔑', name: '/etc/shadow', type: 'Shadow Password File', color: 'var(--magenta)' },
    { icon: '🗄️', name: 'MySQL Dump', type: 'Database Dump', color: 'var(--amber)' },
    { icon: '⚙️', name: 'config.json', type: 'App Config + API Keys', color: 'var(--purple)' },
    { icon: '🔐', name: 'id_rsa', type: 'SSH Private Key', color: 'var(--lime)' },
    { icon: '🌐', name: 'SQL Result', type: 'Fake DB Query Result', color: 'var(--threat-high)' },
  ];

  return (
    <div style={{ padding: 16, height: '100%', overflow: 'auto' }}>
      <div style={{ marginBottom: 16 }}>
        <div className="text-xl font-bold">🦎 Chameleon Decoy Lab</div>
        <div className="dim text-sm" style={{ marginTop: 4 }}>
          All decoys generated dynamically based on attacker behavior using Faker + pattern detection
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {DECOY_TYPES.map((d) => (
          <div key={d.name} className="glass-card" style={{ padding: 16, cursor: 'default' }}>
            <div style={{ fontSize: 28, marginBottom: 8 }}>{d.icon}</div>
            <div className="mono text-sm font-bold" style={{ color: d.color }}>{d.name}</div>
            <div className="dim text-xs" style={{ marginTop: 4 }}>{d.type}</div>
            <div style={{ marginTop: 10, padding: '6px 10px', background: 'var(--bg-elevated)', borderRadius: 6 }}>
              <div className="mono text-xs dim">Status: <span style={{ color: 'var(--threat-low)' }}>ACTIVE</span></div>
              <div className="mono text-xs dim">Served: {Math.floor(Math.random() * 100)} times</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;
