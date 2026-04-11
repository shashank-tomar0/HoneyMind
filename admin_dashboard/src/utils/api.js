export const BACKEND_URL = 'http://localhost:5000';

async function apiFetch(path, opts = {}) {
  const res = await fetch(`${BACKEND_URL}/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

export const api = {
  health:        ()       => apiFetch('/health'),
  getStats:      ()       => apiFetch('/stats'),
  getSessions:   (p = 1)  => apiFetch(`/sessions?page=${p}&per_page=50`),
  getSession:    (id)     => apiFetch(`/sessions/${id}`),
  getGeoAttacks: ()       => apiFetch('/geo/attacks'),
  getTimeline:   ()       => apiFetch('/timeline'),
  getTopAttackers: ()     => apiFetch('/top-attackers'),
  getCanaryTokens: ()     => apiFetch('/canary/tokens'),
  getAttackTypes:  ()     => apiFetch('/dashboard/stats/attack-types'),
  getDeviceFootprints: () => apiFetch('/dashboard/stats/devices'),
  deleteAttacker:  (ip)   => apiFetch(`/dashboard/attackers/${encodeURIComponent(ip)}`, { method: 'DELETE' }),
};
