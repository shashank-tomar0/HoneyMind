/**
 * Fake Dashboard Logic
 * Animates numbers, logs, and handles Bait file downloads via the Flask Backend.
 */

// 1. Verify Auth Token (even though they are already trapped)
if (!localStorage.getItem('auth_token')) {
  window.location.href = 'index.html'; // Kick them out if they bypassed login
}

// 2. Animate Fake Telemetry
setInterval(() => {
  const active = parseInt(document.getElementById('activeConns').innerText.replace(',', ''));
  const change = Math.floor(Math.random() * 5) - 2; // -2 to +2
  document.getElementById('activeConns').innerText = (active + change).toLocaleString();
  
  const cpu = Math.max(10, Math.min(95, parseInt(document.getElementById('cpuLoad').innerText) + (Math.floor(Math.random() * 7) - 3)));
  document.getElementById('cpuLoad').innerText = `${cpu}%`;
}, 3000); // Every 3s

// 3. Generate Fake Logs dynamically
const tableBody = document.getElementById('logTableBody');
const services = ['SSH', 'FTP', 'VPN Gateway', 'Internal Auth', 'Kube API'];
const statuses = ['bg-green', 'bg-yellow'];
const statusText = ['GRANTED', 'CHALLENGE'];

function addFakeLog() {
  const tr = document.createElement('tr');
  const now = new Date();
  const time = now.toTimeString().split(' ')[0];
  
  const srv = services[Math.floor(Math.random() * services.length)];
  const ip = `10.0.${Math.floor(Math.random()*5)}.${Math.floor(Math.random()*254)+1}`;
  const stIndex = Math.random() > 0.8 ? 1 : 0; // 20% chance of challenge

  tr.innerHTML = `
    <td>${time}</td>
    <td style="font-family: monospace;">${srv}</td>
    <td style="color: var(--text-muted);">${ip}</td>
    <td><span class="status-badge ${statuses[stIndex]}">${statusText[stIndex]}</span></td>
  `;

  tableBody.insertBefore(tr, tableBody.firstChild);

  // Keep only 8 logs
  if (tableBody.children.length > 8) {
    tableBody.removeChild(tableBody.lastChild);
  }
}

// Initialize logs
for(let i=0; i<6; i++) {
  addFakeLog();
}
// Add new log every 4-8 seconds
setInterval(addFakeLog, Math.random() * 4000 + 4000);


// 4. Handle Bait Download (Canary Proxy)
async function downloadBait(type, filename) {
  // We hit the backend /api/canary/generate endpoint to get a live tracking file
  // This file contains a 1x1 GIF that will ping back to the flask server when opened
  
  try {
    const sessionToken = localStorage.getItem('auth_token') || 'unknown';
    const response = await fetch(`/api/canary/generate?type=${type}&filename=${filename}&session_id=${sessionToken}`);
    if (!response.ok) throw new Error("File generation failed");
    
    // Convert to downloadable blob
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    
    // Log the interaction via our internal API silently
    fetch('/api/honeypot/log/shell', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: localStorage.getItem('auth_token') || 'unknown',
        command: `HTTP_DOWNLOAD ${filename}`,
        response: '200 OK',
        flag_raised: 'ATTEMPTED_DOWNLOAD',
        flag_detail: filename
      })
    }).catch(e => console.log(e)); // Ignore errors to remain stealthy

  } catch (err) {
    console.error("Download failed", err);
    alert("Intranet Error: The file server is currently down for maintenance.");
  }
}
