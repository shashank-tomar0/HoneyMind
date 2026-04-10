import { create } from 'zustand';

const MAX_FEED = 200;
const MAX_ARCS = 120;
const MAX_ANOMALIES = 30;

// Honeypot location (India)
const HONEYPOT = { lat: 20.5937, lng: 78.9629 };

const useThreatStore = create((set, get) => ({
  // ── State ─────────────────────────────────────────────────────────────────
  connected: false,
  activeSessions: {},          // session_id → session obj
  feedEvents: [],              // last N attack events for the live feed
  globeArcs: [],               // arcs for the 3D globe
  anomalies: [],               // anomaly alert objects
  stats: {
    total_sessions: 0,
    active_sessions: 0,
    threat_levels: {},
    attack_vectors: {},
    top_countries: [],
    attacker_profiles: {},
    avg_threat_score: 0,
    total_events: 0,
  },
  selectedSessionId: null,

  // ── Actions ───────────────────────────────────────────────────────────────
  setConnected: (v) => set({ connected: v }),

  handleNewAttack: (data) => {
    const { session } = data;
    if (!session) return;
    set((state) => ({
      activeSessions: {
        ...state.activeSessions,
        [session.session_id]: session,
      },
    }));
  },

  handleAttackEvent: (event) => {
    const threatLevel = (event.threat_level || 'LOW').toLowerCase();
    const newArc = {
      id: `${event.session_id}-${Date.now()}`,
      startLat: event.geo?.lat || 0,
      startLng: event.geo?.lng || 0,
      endLat: HONEYPOT.lat,
      endLng: HONEYPOT.lng,
      color: LEVEL_COLORS[threatLevel] || LEVEL_COLORS.low,
      label: `${event.geo?.country || 'Unknown'} → HoneyMind`,
      threat_level: event.threat_level,
      attack_type: event.attack_type,
      country: event.geo?.country,
      country_code: event.geo?.country_code,
      city: event.geo?.city,
      ts: Date.now(),
    };

    const feedEntry = {
      id: `${event.session_id}-${Date.now()}-${Math.random()}`,
      session_id: event.session_id,
      timestamp: event.timestamp,
      attack_type: event.attack_type,
      threat_level: event.threat_level,
      threat_score: event.threat_score,
      payload: event.payload,
      country: event.geo?.country,
      country_code: event.geo?.country_code,
      city: event.geo?.city,
      attacker_ip: event.attacker_ip,
      attack_vector: event.attack_vector,
      attacker_profile: event.attacker_profile,
      classification_confidence: event.classification_confidence,
      anomaly_score: event.anomaly_score,
      is_anomaly: event.is_anomaly,
      real_ip: event.real_ip || null,
    };

    set((state) => {
      const newArcs = [newArc, ...state.globeArcs].slice(0, MAX_ARCS);
      const newFeed = [feedEntry, ...state.feedEvents].slice(0, MAX_FEED);

      // Update active session
      const updatedSessions = { ...state.activeSessions };
      if (event.session) {
        updatedSessions[event.session_id] = event.session;
      }

      return {
        globeArcs: newArcs,
        feedEvents: newFeed,
        activeSessions: updatedSessions,
      };
    });
  },

  handleAnomalyAlert: (anomaly) => {
    set((state) => ({
      anomalies: [
        { ...anomaly, id: Date.now() },
        ...state.anomalies,
      ].slice(0, MAX_ANOMALIES),
    }));
  },

  handleSessionEnded: (data) => {
    set((state) => {
      const sessions = { ...state.activeSessions };
      if (sessions[data.session_id]) {
        sessions[data.session_id].is_active = false;
      }
      return { activeSessions: sessions };
    });
  },

  handleStatsUpdate: (stats) => set({ stats }),

  setSelectedSession: (id) => set({ selectedSessionId: id }),

  dismissAnomaly: (id) => set((state) => ({
    anomalies: state.anomalies.filter((a) => a.id !== id),
  })),

  // ── Derived helpers ──────────────────────────────────────────────────────
  getActiveSessionsList: () => {
    const { activeSessions } = get();
    return Object.values(activeSessions)
      .filter((s) => s.is_active)
      .sort((a, b) => (b.threat_score || 0) - (a.threat_score || 0));
  },

  getRecentSessions: () => {
    const { activeSessions } = get();
    return Object.values(activeSessions)
      .sort((a, b) => new Date(b.start_time) - new Date(a.start_time))
      .slice(0, 50);
  },
}));

const LEVEL_COLORS = {
  low:      '#22c55e',
  medium:   '#fbbf24',
  high:     '#f97316',
  critical: '#ef4444',
};

export default useThreatStore;
export { LEVEL_COLORS, HONEYPOT };
