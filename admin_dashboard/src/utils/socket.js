import { io } from 'socket.io-client';
import useThreatStore from '../store/threatStore';

const BACKEND_URL = 'http://localhost:5000';

let socket = null;

export function connectSocket() {
  // Disconnect existing socket to prevent duplicates (React StrictMode)
  if (socket) {
    socket.disconnect();
    socket = null;
  }

  socket = io(BACKEND_URL, {
    transports: ['websocket', 'polling'],
    reconnectionAttempts: 10,
    reconnectionDelay: 1500,
  });

  const store = useThreatStore.getState();

  socket.on('connect', () => {
    console.log('[WS] Connected ');
    store.setConnected(true);
    socket.emit('request_stats');
    socket.emit('request_sessions');
  });

  socket.on('disconnect', () => {
    console.log('[WS] Disconnected ');
    store.setConnected(false);
  });

  socket.on('new_attack',     (data) => store.handleNewAttack(data));
  socket.on('attack_event',   (data) => store.handleAttackEvent(data));
  socket.on('anomaly_alert',  (data) => store.handleAnomalyAlert(data));
  socket.on('session_ended',  (data) => store.handleSessionEnded(data));
  socket.on('stats_update',   (data) => store.handleStatsUpdate(data));
  socket.on('sessions_snapshot', (sessions) => {
    sessions.forEach((s) => store.handleNewAttack({ session: s }));
  });

  return socket;
}

export function disconnectSocket() {
  socket?.disconnect();
}

export { BACKEND_URL };
