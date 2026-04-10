import React, { useEffect, useState } from 'react';
import './index.css';
import Sidebar from './components/common/Sidebar';
import Header from './components/common/Header';
import CommandCenter from './components/Dashboard/CommandCenter';
import AttackerProfile from './components/Attacker/AttackerProfile';
import AIInsights from './components/AI/AIInsights';
import DecoyLab from './components/Decoy/DecoyLab';
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

export default App;
