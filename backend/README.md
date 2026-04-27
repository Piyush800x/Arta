# ARTA Backend — Setup & Run Guide

**Autonomous Red Team Agent v2.0 | Bot to Agent Hackathon | IEM Kolkata | 27 April 2026**

---

## Prerequisites

Install these before the hackathon starts:

```bash
# System tools
sudo apt install nmap metasploit-framework python3.11 python3-pip

# Python package manager (fast)
pip install uv --break-system-packages
```

---

## Night-Before Setup (do this once)

### 1. Download NVD CVE feed
```bash
cd backend/data
curl -o nvd_cve.json.gz https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz
gunzip nvd_cve.json.gz
```

### 2. Download ExploitDB index
```bash
git clone https://gitlab.com/exploit-database/exploitdb.git /tmp/exploitdb
cp /tmp/exploitdb/files_exploits.csv backend/data/exploitdb.csv
```

### 3. Set up Metasploitable 2 VM
- Import the Metasploitable 2 OVA into VirtualBox
- Set network adapter to Host-Only (so it's reachable from your machine only)
- Note its IP — typically `192.168.56.101`
- Verify: `nmap -sV 192.168.56.101` should show vsftpd 2.3.4, Samba 3.x, Apache 2.2

### 4. Test Gemini API key
```bash
curl -H "Content-Type: application/json" \
     -d '{"contents":[{"parts":[{"text":"Hello"}]}]}' \
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=YOUR_KEY"
```

---

## Installation

```bash
cd backend

# Copy and fill in your environment variables
cp .env.example .env
# Edit .env: set GEMINI_API_KEY and METASPLOITABLE_IP

# Install Python dependencies
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

---

## Running the Backend

```bash
# From the backend/ directory, with venv activated
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API is now live at `http://localhost:8000`.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Start a new scan session |
| `GET`  | `/scan/{id}/stream` | SSE log stream (consumed by Next.js) |
| `GET`  | `/scan/{id}` | Session status + findings |
| `GET`  | `/report/{id}` | Full report JSON (for PDF rendering) |

### Start a scan (curl example)
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "192.168.56.101",
    "scan_depth": "standard",
    "authorised": true
  }'
```

Response:
```json
{
  "session_id": "abc123-...",
  "status": "started",
  "stream_url": "/scan/abc123-.../stream"
}
```

### Watch the SSE stream (curl example)
```bash
curl -N http://localhost:8000/scan/abc123-.../stream
```

---

## Demo Mode (exploit fixture)

If Metasploit is unreliable at the venue, set `DEMO_MODE=true` in `.env`.

- The exploit agent returns pre-recorded vsftpd shell output
- Gemini still runs live to evaluate the output — judges see real AI reasoning
- All other agents (Recon, Vuln, Report) run fully live

---

## Project Structure

```
backend/
├── main.py              # FastAPI app — HTTP + SSE endpoints
├── config.py            # Environment variables (single source of truth)
├── db.py                # SQLite schema + async query helpers
├── events.py            # Log event factory + queue broadcaster
├── gemini_client.py     # Gemini API wrapper with rate-limit delay
├── sandbox.py           # Safe subprocess execution for PoC scripts
├── agents/
│   ├── orchestrator.py  # Mission planner — runs the agent chain
│   ├── recon.py         # Nmap + Gemini XML parsing
│   ├── vuln.py          # CVE matching + Gemini ranking
│   ├── exploit.py       # MSF + Gemini PoC generation + self-healing
│   └── report.py        # Gemini report synthesis → report.json
├── tools/
│   ├── nmap_runner.py   # subprocess wrapper for nmap
│   ├── msf_runner.py    # subprocess wrapper for msfconsole
│   └── cve_lookup.py    # local NVD + ExploitDB lookup (no API)
├── data/
│   ├── nvd_cve.json     # pre-downloaded (see night-before setup)
│   └── exploitdb.csv    # pre-downloaded (see night-before setup)
└── requirements.txt
```

---

## Gemini Free Tier Budget per Scan

| Agent | Calls | ~Tokens |
|-------|-------|---------|
| Orchestrator | 1 | ~500 |
| Recon | 1 | ~2,000 |
| Vuln | 1 | ~4,000 |
| Exploit (top 3 CVEs) | 6–8 | ~12,000 |
| Report | 1 | ~8,000 |
| **Total** | **~12** | **~26,000** |

Free tier limit: **15 req/min, 1M tokens/day** — 3 demo runs = 36 calls, 78k tokens. ✅
