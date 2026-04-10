import React, { useRef, useCallback, useMemo } from 'react';
import Globe from 'react-globe.gl';
import useThreatStore, { LEVEL_COLORS, HONEYPOT } from '../../store/threatStore';
import './ThreatGlobe.css';

const HONEYPOT_LABEL = { lat: HONEYPOT.lat, lng: HONEYPOT.lng, label: '🍯 HoneyMind HQ', size: 1.2 };

export default function ThreatGlobe({ onArcClick }) {
  const globeRef = useRef(null);
  const { globeArcs } = useThreatStore();

  // Deduplicate arcs by country to avoid clutter, keep most recent
  const displayArcs = useMemo(() => {
    const seen = new Map();
    for (const arc of globeArcs) {
      const key = `${arc.startLat?.toFixed(1)},${arc.startLng?.toFixed(1)}`;
      if (!seen.has(key) || arc.ts > seen.get(key).ts) {
        seen.set(key, arc);
      }
    }
    return Array.from(seen.values()).slice(0, 80);
  }, [globeArcs]);

  // Pulse rings on the honeypot
  const ringsData = useMemo(() => [
    { lat: HONEYPOT.lat, lng: HONEYPOT.lng, maxR: 5, propagationSpeed: 2, repeatPeriod: 900, color: 'rgba(0,240,255,0.6)' },
    { lat: HONEYPOT.lat, lng: HONEYPOT.lng, maxR: 8, propagationSpeed: 1.5, repeatPeriod: 1400, color: 'rgba(0,240,255,0.3)' },
  ], []);

  const arcColor = useCallback((d) => {
    const level = (d.threat_level || 'LOW').toLowerCase();
    return [LEVEL_COLORS[level] || '#22c55e', 'rgba(0,240,255,0.1)'];
  }, []);

  const handleArcHover = useCallback((arc) => {
    if (arc && globeRef.current) {
      globeRef.current.pointOfView({ lat: arc.startLat, lng: arc.startLng, altitude: 1.8 }, 800);
    }
  }, []);

  return (
    <div className="globe-wrapper">
      <Globe
        ref={globeRef}
        width={undefined}
        height={undefined}
        backgroundColor="rgba(0,0,0,0)"
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
        bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"

        // Attack arcs
        arcsData={displayArcs}
        arcStartLat={(d) => d.startLat}
        arcStartLng={(d) => d.startLng}
        arcEndLat={(d) => d.endLat}
        arcEndLng={(d) => d.endLng}
        arcColor={arcColor}
        arcDashLength={0.4}
        arcDashGap={0.2}
        arcDashAnimateTime={2200}
        arcStroke={0.5}
        arcAltitudeAutoScale={0.3}
        onArcClick={onArcClick}
        onArcHover={handleArcHover}

        // Honeypot pulse rings
        ringsData={ringsData}
        ringColor={(d) => d.color}
        ringMaxRadius="maxR"
        ringPropagationSpeed="propagationSpeed"
        ringRepeatPeriod="repeatPeriod"

        // Honeypot label point
        pointsData={[HONEYPOT_LABEL]}
        pointLat="lat"
        pointLng="lng"
        pointColor={() => '#00f0ff'}
        pointAltitude={0.02}
        pointRadius={0.5}
        pointLabel="label"

        atmosphereColor="#0088aa"
        atmosphereAltitude={0.15}

        enablePointerInteraction={true}
      />
      <div className="globe-legend">
        {Object.entries(LEVEL_COLORS).map(([level, color]) => (
          <div key={level} className="legend-item">
            <span className="legend-dot" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
            <span className="legend-label mono text-xs">{level.toUpperCase()}</span>
          </div>
        ))}
      </div>
      <div className="globe-count mono text-xs dim">
        {displayArcs.length} active arcs
      </div>
    </div>
  );
}
