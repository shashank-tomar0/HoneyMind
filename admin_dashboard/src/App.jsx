import React, { useEffect, useState } from 'react';
import './index.css';
import Sidebar from './components/common/Sidebar';
import Header from './components/common/Header';
import CommandCenter from './components/Dashboard/CommandCenter';
import AttackerProfile from './components/Attacker/AttackerProfile';
import AIInsights from './components/AI/AIInsights';
import { connectSocket } from './utils/socket';
import useThreatStore from './store/threatStore';
import { api } from './utils/api';

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

// Dynamic Decoy Lab Component
function DecoyLab() {
  const [tokens, setTokens] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getCanaryTokens()
      .then(data => {
        setTokens(data.tokens || {});
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  const getIconForType = (type) => {
    switch(type) {
      case 'html': return '';
      case 'xlsx': return '';
      case 'pdf': return '';
      case 'docx': return '';
      default: return '';
    }
  };

  const getColorForType = (type) => {
    switch(type) {
      case 'html': return 'var(--cyan)';
      case 'xlsx': return 'var(--amber)';
      case 'pdf': return 'var(--magenta)';
      case 'docx': return 'var(--purple)';
      default: return 'var(--lime)';
    }
  };

  const tokenEntries = Object.entries(tokens);

  return (
    <div style={{ padding: 16, height: '100%', overflow: 'auto' }}>
      <div style={{ marginBottom: 16 }}>
        <div className="text-xl font-bold"> Chameleon Decoy Lab</div>
        <div className="dim text-sm" style={{ marginTop: 4 }}>
          Live generated decoys currently staged or deployed in the honeypot
        </div>
      </div>
      
      {loading ? (
        <div className="dim">Loading active decoys...</div>
      ) : tokenEntries.length === 0 ? (
        <div className="dim">No decoys currently active. Wait for attacker interaction or generate manually.</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
          {tokenEntries.map(([id, t]) => (
            <div key={id} className="glass-card" style={{ padding: 16, cursor: 'default' }}>
              <div style={{ fontSize: 28, marginBottom: 8 }}>{getIconForType(t.file_type)}</div>
              <div className="mono text-sm font-bold" style={{ color: getColorForType(t.file_type) }}>
                {t.file_name || 'unknown'}
              </div>
              <div className="dim text-xs" style={{ marginTop: 4 }}>Type: {t.file_type.toUpperCase()}</div>
              <div className="dim text-xs" style={{ marginTop: 4, opacity: 0.6 }}>ID: {id.split('-')[0]}...</div>
              <div style={{ marginTop: 10, padding: '6px 10px', background: 'var(--bg-elevated)', borderRadius: 6 }}>
                <div className="mono text-xs dim">Status: <span style={{ color: 'var(--threat-low)' }}>ACTIVE</span></div>
                <div className="mono text-xs dim">Generated: {new Date(t.created_at).toLocaleTimeString()}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default App;
