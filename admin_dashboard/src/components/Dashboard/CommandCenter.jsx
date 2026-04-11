import React from 'react';
import StatsPanel from './StatsPanel';
import LiveFeed from './LiveFeed';
import ThreatChart from './ThreatChart';
import ThreatGlobe from '../Globe/ThreatGlobe';
import AIInsights from '../AI/AIInsights';
import AnomalyAlerts from '../AI/AnomalyAlerts';
import useThreatStore from '../../store/threatStore';
import './CommandCenter.css';

export default function CommandCenter({ onSelectSession }) {
  const { feedEvents, stats } = useThreatStore();

  return (
    <div className="cc-organized-root">
      {/* Left side: All analytics and monitoring UI */}
      <div className="cc-left-pane">
        
        {/* Unified Stats Ribbon */}
        <div className="cc-section-block">
          <StatsPanel />
        </div>

        {/* Charts & AI */}
        <div className="cc-middle-grid">
          <div className="cc-grid-cell">
            <ThreatChart />
          </div>
          <div className="cc-grid-cell cc-ai-cell">
            <AIInsights />
          </div>
        </div>

        {/* Live Feed & Anomalies */}
        <div className="cc-bottom-grid">
          <div className="cc-feed-cell">
            <LiveFeed onSelectSession={onSelectSession} />
          </div>
          <div className="cc-alerts-cell">
            <AnomalyAlerts />
          </div>
        </div>
        
      </div>

      {/* Right side: Globe Panel */}
      <div className="cc-right-pane glass-card">
        <div className="cc-globe-header mono dim text-xs">GLOBAL THREAT MAP</div>
        <ThreatGlobe onArcClick={(arc) => {
          if (arc?.session_id) onSelectSession?.(arc.session_id);
        }} />
      </div>
    </div>
  );
}
