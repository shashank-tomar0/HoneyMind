import React, { useState } from 'react';
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
    <div className="cc-root">
      {/* 1. Full-Bleed Background Globe Layer */}
      <div className="cc-globe-layer">
        <ThreatGlobe onArcClick={(arc) => {
          if (arc?.session_id) onSelectSession?.(arc.session_id);
        }} />
      </div>

      {/* 2. Floating UI Overlay Layer */}
      <div className="cc-ui-overlay">
        
        {/* Top: Stats Blocks */}
        <div className="cc-stats-row">
          <StatsPanel />
        </div>

        {/* Middle: Empty Space (to see globe) + Right Side Panels */}
        <div className="cc-middle-row">
          {/* Spacer to push panels to the right */}
          <div className="cc-globe-spacer" />
          
          <div className="cc-right-panels">
            <div className="cc-ai-panel">
              <AIInsights />
            </div>
            <div className="cc-chart-panel">
              <ThreatChart />
            </div>
          </div>
        </div>

        {/* Bottom: Feed and Alerts */}
        <div className="cc-bottom-row">
          <div className="cc-feed-wrapper">
             <LiveFeed onSelectSession={onSelectSession} />
          </div>
          <AnomalyAlerts />
        </div>

      </div>
    </div>
  );
}
