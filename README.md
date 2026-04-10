# 🐝 HoneyShield – AI-Powered Cyber Deception & Intelligence Platform

> **"Don't just block attacks. Turn them into intelligence."**

HoneyShield is a full-stack honeypot system that detects malicious login attempts using an ML pipeline, engages attackers in a controlled fake environment, tracks their real identity via canary tokens, and generates structured threat intelligence reports — fully offline, no external AI API required.

---

## 📌 Table of Contents

1. [Problem Statement](#-problem-statement)
2. [Solution Overview](#-solution-overview)
3. [System Architecture](#-system-architecture)
4. [Module Breakdown](#-module-breakdown)
5. [ML Pipeline](#-ml-pipeline)
6. [Fake Services](#-fake-services)
7. [Canary Token System](#-canary-token-system)
8. [Intelligence Layer](#-intelligence-layer)
9. [Dashboard & Reporting](#-dashboard--reporting)
10. [Tech Stack](#-tech-stack)
11. [Project Structure](#-project-structure)
12. [Configuration](#-configuration)
13. [Setup & Running](#-setup--running)
14. [Legal & Ethical Notes](#-legal--ethical-notes)
15. [Future Scope](#-future-scope)

---

## 🎯 Problem Statement

Traditional security systems block attacks but:
- Provide **no behavioral insight** into attacker methodology
- Fail against **VPN/proxy-masked** attackers
- Generate **no actionable threat intelligence**
- Cannot differentiate between **bots, script kiddies, and APT-level attackers**

---

## 💡 Solution Overview

HoneyShield acts as a **trap system** that:

1. Uses an **ML pipeline** to classify every login as `ATTACKER / SUSPICIOUS / LEGIT`
2. Routes attackers into **fake services** (SSH, FTP, Admin Panel) without alerting them
3. Engages them with **dynamically generated fake data** to keep them active longer
4. Tracks their **real IP** (bypasses VPN) via canary token-embedded bait files
5. Captures every command, credential, and behavioral signal
6. Generates a structured **threat intelligence report** per session

---

## 🏗️ System Architecture

```
Attacker
   ↓
Adaptive Entry Layer
(Fake website / Admin Panel with JS behavioral tracking)
   ↓
Detection Engine
(Brute force / SQLi / Port scan — rule-based pre-filter)
   ↓
ML Pipeline — Login Classifier
   ├── Phase 1: Isolation Forest (cold start, unsupervised)
   └── Phase 2: Random Forest (supervised, post label collection)
   ↓
Routing Decision
   ├── ATTACKER  (≥ 0.75) → Activate Honeypot
   ├── SUSPICIOUS (0.45–0.74) → Soft monitor + log
   └── LEGIT      (< 0.45)  → Allow through
   ↓
Honeypot Layer
   ├── Fake SSH Service     → fake shell, command logger
   ├── Fake FTP Service     → fake file server, canary files
   └── Fake Admin Panel     → dynamic fake data, bait download
   ↓
Canary Token System
(Bait file opened on attacker machine → real IP callback)
   ↓
Intelligence Layer
   ├── IP Enrichment       → geolocation, ISP, VPN hint
   ├── Behavioral Scorer   → risk score 1–10
   └── Threat Report       → structured session summary
   ↓
Dashboard (live) + PDF Report + Alert Webhook
```

---

## 📦 Module Breakdown

### 1. `detection_engine/`

Rule-based pre-filter that runs before the ML pipeline.

| File | Responsibility |
|------|---------------|
| `brute_force_detector.py` | Tracks failed attempts per IP per time window |
| `sqli_detector.py` | Regex + pattern match for SQLi payloads in form fields |
| `port_scan_detector.py` | Detects rapid sequential port probing |

**Brute force threshold (configurable):**
```python
MAX_ATTEMPTS = 5       # attempts before flagging
TIME_WINDOW_S = 60     # rolling window in seconds
```

If IP exceeds threshold → immediately bypasses ML pipeline → routes straight to honeypot.

---

### 2. `ml_pipeline/`

Core classification engine. Decides whether a login is from an attacker or a legitimate user.

#### Feature Vector (12 signals)

| # | Feature | Type | Signal |
|---|---------|------|--------|
| 0 | `time_to_submit_form_s` | float | Bots < 1s, humans 3–8s |
| 1 | `attempts_per_minute` | int | High = brute force |
| 2 | `is_vpn` | bool | VPN detected |
| 3 | `is_tor` | bool | TOR exit node |
| 4 | `ip_abuse_score` | int | AbuseIPDB score 0–100 (locally cached) |
| 5 | `username_is_common` | bool | admin, root, test, guest, ubuntu |
| 6 | `password_in_wordlist` | bool | Match in top-10k rockyou.txt |
| 7 | `user_agent_is_headless` | bool | Headless Chrome = bot |
| 8 | `has_javascript` | bool | Bots often skip JS execution |
| 9 | `mouse_moved_before_click` | bool | Human behavioral signal |
| 10 | `keystroke_interval_ms` | float | Bots are too fast and too uniform |
| 11 | `request_hour` | int | 2–5 AM = elevated risk |

#### Two-Phase Model Strategy

**Phase 1 — Isolation Forest (deploy from day 0)**
- Unsupervised anomaly detection
- Trains on normal/legit sessions only
- No labeled attacker data needed
- Flags statistical outliers as anomalies

**Phase 2 — Random Forest (after ~500 labeled sessions)**
- Supervised binary classification (`0 = legit`, `1 = attacker`)
- `class_weight="balanced"` handles imbalanced attacker/legit ratio
- Weekly auto-retraining via scheduler
- Produces feature importance chart

#### Confidence Routing

```
Score ≥ 0.75  →  ATTACKER    →  activate honeypot
Score 0.45–0.74  →  SUSPICIOUS  →  log heavily, soft monitor
Score < 0.45   →  LEGIT      →  allow through
```

#### Files

| File | Responsibility |
|------|---------------|
| `feature_extractor.py` | Converts raw session dict → 12-dim numpy array |
| `classifier.py` | Loads model, runs predict(), returns action |
| `trainer.py` | `train_phase1()`, `train_phase2()`, scheduled weekly retrain |
| `evaluator.py` | Confusion matrix, classification report, feature importance chart |
| `label_store.py` | Stores Phase 1 flagged sessions for manual labeling |
| `models/phase1_isolation.pkl` | Trained Isolation Forest |
| `models/phase2_rf_latest.pkl` | Latest Random Forest |
| `models/scaler.pkl` | Fitted StandardScaler |
| `wordlists/top10k_passwords.txt` | Common password list for feature 6 |

---

### 3. `honeypot_services/`

Fake network services that look real. Every interaction is silently logged.

#### `fake_ssh.py`

- Built with `paramiko`
- Listens on port `2222`
- Delays denial with `random.uniform(1.0, 2.5)` seconds — mimics real SSH
- Grants fake access after **2–4 failed attempts**
- Drops attacker into a fully fake interactive shell

**Fake shell command responses:**

| Command | Fake Response |
|---------|--------------|
| `whoami` | `admin` |
| `id` | `uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)` |
| `uname -a` | `Linux prod-server-01 5.15.0-91-generic x86_64 GNU/Linux` |
| `cat /etc/passwd` | fake passwd entries |
| `ls` | `documents downloads .ssh .bash_history` |
| `ifconfig` | fake internal IP |

**High-value detection flags inside fake shell:**

| Command pattern | Flag raised |
|----------------|-------------|
| `wget` / `curl` | `ATTEMPTED_DOWNLOAD` — captures target URL |
| `chmod +x` / `./exploit` | `ATTEMPTED_EXECUTION` |
| `ssh user@<ip>` | `PIVOTING_ATTEMPT` — captures new target IP |
| `cat /etc/shadow` | `PRIVILEGE_ESCALATION` |
| `crontab -e` | `PERSISTENCE_ATTEMPT` |

#### `fake_ftp.py`

- Built with `pyftpdlib`
- Impersonates `Microsoft FTP Service` banner
- Accepts all credentials (anonymous + common defaults)
- Serves canary-embedded fake files:
  - `backups/db_dump_2024.sql`
  - `private/employee_records.csv`
  - `config/credentials.txt`
  - `config/settings.env`
- Every file downloaded triggers canary token ping

#### `fake_shell.py`

- Shared fake shell logic used by SSH service
- Maintains per-session command history
- Raises flags on dangerous command patterns
- Returns contextually believable fake responses

---

### 4. `fake_admin_panel/`

Web-based honeypot mimicking a real admin dashboard.

**Backend (FastAPI):**
- Serves fake metrics, fake user tables, fake revenue data
- "Download DB Backup" button → serves canary-embedded bait file
- Logs every page visit, form interaction, button click

**Frontend (React):**
- Looks like a real internal admin tool
- JS behavioral tracker embedded:
  - Mouse movement pattern
  - Typing speed
  - Click heatmap
  - Time-on-page per section
  - Whether DevTools is open

---

### 5. `canary_token_system/`

Tracks attacker's **real IP address**, bypassing VPN.

**How it works:**
```
Attacker downloads bait file from honeypot
        ↓
File contains embedded tracking beacon
        ↓
Attacker opens file on their machine
        ↓
Outbound HTTP request fires from INSIDE their network
        ↓
Your server captures: real IP, ISP, OS, browser, timestamp
```

Even if they used a VPN to attack — the file opens inside their real network, bypassing it entirely.

**Bait file types:**

| Type | Trigger mechanism | Effectiveness |
|------|------------------|---------------|
| HTML | `<img>` beacon on open | Medium |
| XLSX | External data connection | Very High |
| PDF | Embedded URL on open | High |
| DOCX | Remote template fetch | High |

**API Endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /canary/ping/{token}` | Logs hit, returns 1x1 transparent GIF |
| `GET /generate-bait?type=xlsx` | Generates canary-embedded bait file |
| `GET /canary/hits` | Dashboard — all triggered tokens |

**Files:**

| File | Responsibility |
|------|---------------|
| `generator.py` | Creates UUID-linked bait files with embedded beacon |
| `tracker.py` | FastAPI endpoints, logs hits to DB |
| `bait_files/` | Template files for each bait type |

---

### 6. `intelligence_layer/`

Enriches raw captured data into a structured threat profile.

#### `ip_enricher.py`

- Uses `ipapi.co` free tier (no API key needed for basic)
- Returns: city, region, country, ISP, VPN hint
- Cross-references locally cached AbuseIPDB data

#### `behavioral_scorer.py`

Produces a risk score (1–10) per session:

| Signal | Score Added |
|--------|------------|
| > 10 credential attempts | +2 |
| Common username used | +1 |
| Wordlist password used | +1 |
| `/etc/passwd` accessed | +1 |
| File download attempted | +2 |
| Canary token triggered | +2 |
| Pivoting attempt detected | +3 |
| Privilege escalation attempt | +3 |

#### `report_builder.py`

Compiles full session data into a structured threat report dict:

```python
{
    "session_id": "uuid",
    "timestamp": "2025-04-10T03:22:11Z",
    "duration_seconds": 183,
    "attacker_ip": "x.x.x.x",
    "real_ip_via_canary": "y.y.y.y",
    "geolocation": { "city": "...", "country": "...", "isp": "..." },
    "is_vpn": True,
    "services_probed": ["ssh", "ftp", "admin_panel"],
    "credentials_tried": [...],
    "shell_commands": [...],
    "flags_raised": ["ATTEMPTED_DOWNLOAD", "PIVOTING_ATTEMPT"],
    "canary_hit": { "triggered": True, "file": "db_backup.xlsx" },
    "risk_score": 8,
    "ml_confidence": 0.91,
    "ml_phase": 2
}
```

---

### 7. `dashboard/`

Live monitoring and session visualization.

**Features:**
- Live attack feed via WebSocket
- World map of attacker geolocations (Chart.js + GeoJSON)
- Attack type breakdown: brute force vs SQLi vs port scan
- ML confidence score per session
- Behavioral risk score timeline
- Session replay: scrub through attacker session chronologically
- Top attacked services breakdown

---

### 8. `reporting/`

Auto-generates a PDF report per completed attacker session.

**Each report includes:**
- Session overview (start time, duration, services probed)
- IP intelligence (geo, ISP, VPN status, canary real IP)
- Credential attempts log
- Full shell command history (SSH sessions)
- Flags raised with explanations
- Risk score breakdown
- Recommended defensive action

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend API | FastAPI (Python) |
| Fake SSH | paramiko |
| Fake FTP | pyftpdlib |
| ML Pipeline | scikit-learn (Isolation Forest + Random Forest) |
| Frontend / Admin Panel | React + Chart.js |
| IP Enrichment | ipapi.co (free tier, locally cached) |
| Database | PostgreSQL |
| Session / Cache Store | Redis |
| PDF Reports | ReportLab |
| Scheduler | schedule (Python) |
| Containerization | Docker + Docker Compose |

---

## 📁 Project Structure

```
honeyshield/
│
├── detection_engine/
│   ├── brute_force_detector.py
│   ├── sqli_detector.py
│   └── port_scan_detector.py
│
├── ml_pipeline/
│   ├── feature_extractor.py
│   ├── classifier.py
│   ├── trainer.py
│   ├── evaluator.py
│   ├── label_store.py
│   ├── wordlists/
│   │   └── top10k_passwords.txt
│   └── models/
│       ├── phase1_isolation.pkl
│       ├── phase2_rf_latest.pkl
│       └── scaler.pkl
│
├── honeypot_services/
│   ├── fake_ssh.py
│   ├── fake_ftp.py
│   └── fake_shell.py
│
├── fake_admin_panel/
│   ├── backend/
│   │   └── main.py              # FastAPI app
│   └── frontend/
│       └── src/                 # React app
│
├── canary_token_system/
│   ├── generator.py
│   ├── tracker.py
│   └── bait_files/
│       ├── template.html
│       ├── template.xlsx
│       └── template.pdf
│
├── intelligence_layer/
│   ├── ip_enricher.py
│   ├── behavioral_scorer.py
│   └── report_builder.py
│
├── dashboard/
│   ├── backend/
│   │   └── ws_server.py         # WebSocket server
│   └── frontend/
│       └── src/                 # React live dashboard
│
├── reporting/
│   └── pdf_generator.py
│
├── database/
│   ├── models.py                # SQLAlchemy models
│   ├── crud.py                  # DB operations
│   └── migrations/
│
├── config.yaml
├── docker-compose.yml
├── requirements.txt
└── main.py                      # Orchestrator — starts all services
```

---

## ⚙️ Configuration (`config.yaml`)

```yaml
detection:
  brute_force_max_attempts: 5
  brute_force_window_seconds: 60

ml_pipeline:
  phase2_min_samples: 500
  confidence_attacker_threshold: 0.75
  confidence_suspicious_threshold: 0.45
  retrain_schedule: "monday 02:00"

services:
  ssh_port: 2222
  ftp_port: 21
  admin_panel_port: 8080

auth:
  min_attempts_before_grant: 2
  max_attempts_before_grant: 4
  denial_delay_min: 1.0
  denial_delay_max: 2.5

canary:
  server_url: "https://yourdomain.com"
  bait_file_types: ["html", "xlsx", "pdf"]

intelligence:
  geoip_provider: "ipapi.co"
  abuseipdb_cache_ttl_hours: 24

alerts:
  webhook_url: "${ALERT_WEBHOOK_URL}"
  min_risk_score_to_alert: 7

database:
  url: "postgresql://user:pass@localhost:5432/honeyshield"

redis:
  url: "redis://localhost:6379"
```

---

## 🚀 Setup & Running

```bash
# 1. Clone repo
git clone https://github.com/raidx545/honeyshield
cd honeyshield

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set environment variables
export ALERT_WEBHOOK_URL=your_webhook

# 4. Train Phase 1 model (run once on startup)
python -c "from ml_pipeline.trainer import train_phase1; train_phase1([])"

# 5. Start all services
docker-compose up

# OR run directly
python main.py
```

**Services started by `main.py`:**
- Fake SSH on port `2222`
- Fake FTP on port `21`
- Admin Panel API on port `8080`
- Canary token server on port `8081`
- Dashboard WebSocket server on port `8082`
- ML retraining scheduler (background thread)

---

## 🔐 Legal & Ethical Notes

- HoneyShield is a **passive intelligence collection** system
- All fake services run **within your own infrastructure**
- Canary tokens use **outbound HTTP callbacks only** — no code executes on attacker machines
- Collected data should be handled per applicable data protection laws (India IT Act 2000, GDPR where applicable)
- Intended for: cybersecurity research, enterprise threat monitoring, educational use

---

## 🔮 Future Scope

- **Distributed honeypot network** — community threat feed across multiple HoneyShield instances
- **SIEM integration** — export sessions to Splunk / ELK Stack
- **Real-time SMS/email alerts** on high risk-score sessions
- **AgentGuard integration** — syscall-level monitoring of honeypot processes via ptrace/eBPF
- **Attack replay export** — shareable `.hshield` session files for research
- **LLM-generated fake shell responses** — dynamic fake output per command for longer engagement

---

## 👨‍💻 Author

**Raj Porwal (RaidX)**
B.Tech CSE — ABES Engineering College, Ghaziabad
GitHub: [@raidx545](https://github.com/raidx545)
Twitter: [@raaz_porwal](https://twitter.com/raaz_porwal)
LinkedIn: [raj-porwal-329493216](https://linkedin.com/in/raj-porwal-329493216)
