# ARTA — Autonomous Red Team Agent

> Autonomous penetration testing pipeline: Recon → Vuln Analysis → Exploit → PDF Report.
> Powered by Gemini 2.0 Flash. Zero infrastructure cost. Lab target: Metasploitable 2.

---

## Project Layout

```
arta/
├── backend/       # Python — FastAPI + 4 AI agents
└── arta-frontend/ # TypeScript — Next.js 14 dashboard
```

---

## Backend (`backend/`)

### Stack
- **FastAPI** — HTTP API + SSE streaming
- **aiosqlite** — async SQLite (single file `arta.db`)
- **google-generativeai** — Gemini `gemini-flash-lite-latest`
- **httpx** — async HTTP client for live NVD API queries
- **pandas** — ExploitDB CSV lookups (optional)
- **Puppeteer** — PDF generation lives in the Next.js layer, not here

### Run
```bash
cd backend
cp .env.example .env          # fill in GEMINI_API_KEY
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Environment Variables (`.env`)
| Variable | Required | Description |
|----------|----------|-------------|
| `GEMINI_API_KEY` | ✅ | Gemini API key |
| `METASPLOITABLE_IP` | ✅ | Lab VM IP (default `192.168.56.101`) |
| `NVD_API_KEY` | optional | Raises NVD rate limit from 5→50 req/30s |
| `EXPLOITDB_CSV` | optional | Path to `data/exploitdb.csv` |
| `DEMO_MODE` | optional | `true` = use pre-recorded MSF fixture |
| `SQLITE_PATH` | optional | Default `./arta.db` |
| `SESSIONS_TMP` | optional | Default `/tmp/arta_sessions` |
| `SANDBOX_DIR` | optional | Default `/tmp/arta_sandbox` |
| `FRONTEND_URL` | optional | Default `http://localhost:3000` (CORS) |

### API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Start a new scan session |
| `GET` | `/scan/{id}/stream` | SSE log stream (consumed by frontend) |
| `GET` | `/scan/{id}` | Session status + findings list |
| `GET` | `/report/{id}` | Full report JSON (for PDF rendering) |

### File Map
```
backend/
├── main.py                  # FastAPI app — routes, SSE, CORS, lifespan
├── config.py                # All env vars — import from here, never os.getenv() directly
├── db.py                    # SQLite schema + async helpers (sessions, findings, logs)
├── events.py                # emit() — pushes to asyncio.Queue AND SQLite simultaneously
├── gemini_client.py         # ask() / ask_json() — rate-limit delay, JSON fence stripper
├── sandbox.py               # Safe subprocess: RLIMIT_CPU/AS/NPROC, stripped env
├── agents/
│   ├── orchestrator.py      # Mission planner — calls Gemini once, runs chain sequentially
│   ├── recon.py             # nmap via asyncio.to_thread → Gemini XML parser
│   ├── vuln.py              # Live NVD API per service → Gemini ranker → ExploitDB check
│   ├── exploit.py           # MSF module → Gemini PoC → self-heal loop (max 3 retries)
│   └── report.py            # Gemini synthesises full report JSON → writes report.json
└── tools/
    ├── nmap_runner.py        # subprocess wrapper for nmap, returns raw XML
    ├── msf_runner.py         # subprocess wrapper for msfconsole, DEMO_MODE fixture
    └── cve_lookup.py         # NVD API v2 (live) + ExploitDB CSV (local, optional)
```

### Agent Chain
```
POST /scan
  └── orchestrator.run()
        ├── recon.run()         → nmap XML → Gemini parse → recon.json
        ├── vuln.run()          → NVD API × N services → Gemini rank → findings in SQLite
        ├── exploit.run()       → MSF / Gemini PoC → sandbox → self-heal → update findings
        └── report.run()        → Gemini synthesise → report.json → emit PDF_READY
```

### Key Patterns

**Emitting log events** — every agent uses `events.emit()`:
```python
await events.emit(
    session_id, "vuln", "gemini",
    "GEMINI_RANKING 12 CVE(s)",
    tool="gemini_function_call",
    duration_ms=1240,
    payload={"count": 12},
)
```
Log levels: `info` | `gemini` | `success` | `warning` | `error` | `tool`

**Calling Gemini**:
```python
# Plain text response
text = await gemini.ask(prompt)

# JSON response (handles fences + extraction fallback automatically)
data = await gemini.ask_json(prompt)
```
The 4-second inter-call delay is baked into `gemini_client.py` — never add extra `asyncio.sleep()` in agents.

**Running PoC code safely**:
```python
result = sandbox.run_poc(session_id, python_code)
# result = { "stdout": str, "stderr": str, "returncode": int, "timed_out": bool }
```

**NVD API query**:
```python
candidates = await search_by_product("vsftpd", "2.3.4", limit=10)
# Returns list of { cve_id, cvss_v3, severity, cvss_vector, description, cwe, references }
```

### Database Schema (SQLite)

**`sessions`**: `id`, `target_scope`, `scan_depth`, `status`, `created_at`, `completed_at`, `finding_count`, `critical_count`, `report_json_path`

**`findings`**: `id`, `session_id`, `cve_id`, `cvss_v3`, `cvss_vector`, `severity`, `affected_service`, `affected_port`, `detected_version`, `description`, `exploit_available`, `exploit_complexity`, `attack_vector`, `privileges_required`, `user_interaction`, `exploit_source`, `exploit_succeeded`, `shell_access`, `evidence_stdout`, `owasp_category`, `cwe`, `impact`, `remediation_short`, `remediation_package`, `remediation_cmd`, `references`

**`logs`**: `id`, `session_id`, `ts`, `agent`, `level`, `tool`, `message`, `payload`

`findings` uses `INSERT OR REPLACE` so the exploit agent can update the same row without collision.

### Gemini Budget per Scan
| Agent | Calls | ~Tokens |
|-------|-------|---------|
| Orchestrator | 1 | ~500 |
| Recon | 1 | ~2,000 |
| Vuln | 1 | ~4,000 |
| Exploit (×3 CVEs) | 6–9 | ~15,000 |
| Report | 1 | ~12,000 |
| **Total** | **~11** | **~33,500** |

Free tier: 15 req/min, 1M tokens/day. Three demo runs ≈ 33 calls, 100k tokens. ✅

### Night-Before Data Setup
ExploitDB CSV is optional but speeds up exploit checks:
```bash
# Linux/Mac
cd backend && ./setup_data.sh

# Windows / no curl
cd backend && python setup_data.py
```
NVD JSON feed is **no longer needed** — ARTA queries the NVD API live.

---

## Frontend (`arta-frontend/`)

### Stack
- **Next.js 14** (App Router) — pages and API routes
- **TypeScript** — strict mode
- **CSS Modules** — scoped styles, no Tailwind
- **Puppeteer** — headless Chrome for PDF rendering (server-side API route)
- **EventSource** — native browser SSE for the live log stream

### Run
```bash
cd arta-frontend
cp .env.local.example .env.local   # set NEXT_PUBLIC_API_URL if backend is not on :8000
npm install                         # also downloads headless Chrome (~170MB)
npm run dev                         # http://localhost:3000
```

### Environment Variables (`.env.local`)
| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | FastAPI backend URL |

### Page Map
```
/                    → Scan submission form (target IP, depth, auth checkbox)
/scan/[id]           → Live dashboard (SSE stream + stepper + findings + PDF viewer)
```

### API Route Map
```
POST /api/scan                   → Proxies to FastAPI POST /scan
GET  /api/scan/[id]/stream       → SSE proxy — pipes FastAPI stream to browser
GET  /api/report/[id]/pdf        → Fetches report JSON → HTML template → Puppeteer PDF
```

### File Map
```
arta-frontend/src/
├── app/
│   ├── layout.tsx               # Root layout — imports globals.css
│   ├── globals.css              # Design tokens (CSS vars) + animations
│   ├── page.tsx                 # Landing page — scan form
│   ├── page.module.css
│   ├── scan/[id]/
│   │   ├── page.tsx             # Live scan dashboard — SSE consumer
│   │   └── page.module.css
│   └── api/
│       ├── scan/route.ts            # POST proxy
│       ├── scan/[id]/stream/route.ts # SSE proxy
│       └── report/[id]/pdf/route.ts  # Puppeteer PDF renderer
├── components/
│   ├── AgentStepper.tsx         # Horizontal pipeline status bar
│   ├── LogFeed.tsx              # Colour-coded SSE log rows + blinking cursor
│   ├── FindingsTable.tsx        # CVE findings table with severity badges
│   └── ReportViewer.tsx         # iframe PDF preview + download button
├── lib/
│   ├── api.ts                   # Typed fetch wrappers for all backend endpoints
│   └── pdf-template.ts          # HTML template used by Puppeteer
└── types/
    └── index.ts                 # Shared TypeScript types (LogEvent, Finding, Session…)
```

### Design System (CSS Variables)
```css
--black        #080a0c   /* base background */
--green        #00ff41   /* phosphor green — primary accent */
--green-glow   rgba(0,255,65,0.12)
--font-mono    'IBM Plex Mono'
--font-display 'Space Mono'

/* Log level colours */
--col-info     #8b949e   /* gray  — standard status */
--col-gemini   #a371f7   /* purple — every Gemini call */
--col-success  #00ff41   /* green  — exploits landed, steps done */
--col-warning  #d29922   /* amber  — retries, partial results */
--col-error    #f85149   /* red    — failures */
--col-tool     #388bfd   /* blue   — raw tool output */

/* Agent colours */
--agent-orchestrator  #8b949e
--agent-recon         #388bfd
--agent-vuln          #d29922
--agent-exploit       #f85149
--agent-report        #3fb950

/* Severity */
--sev-critical  #ff2d55
--sev-high      #ff9500
--sev-medium    #ffd60a
--sev-low       #30d158
```

### SSE Flow
```
browser EventSource → /api/scan/[id]/stream (Next.js proxy)
                     → FastAPI /scan/{id}/stream
                     ← asyncio.Queue events
                     ← SQLite replay (last 200 events on reconnect)
```

The `scan/[id]/page.tsx` deduplicates events by `id` so reconnects never show duplicates.

### PDF Generation Flow
```
browser GET /api/report/[id]/pdf
  → Next.js API route
  → fetch FastAPI GET /report/{id}  (report JSON)
  → buildReportHtml(report)          (pdf-template.ts)
  → puppeteer.launch()
  → page.setContent(html)
  → page.pdf({ format: "A4" })
  → Response(pdfBuffer, "application/pdf")
```

If Puppeteer fails at the venue, the raw report JSON is always at `GET :8000/report/{id}`.

### Adding a New Component
1. Create `src/components/MyComponent.tsx` + `MyComponent.module.css`
2. Use CSS variables from `globals.css` — never hardcode colours
3. Import in the relevant page — no global registry needed

---

## Common Tasks

### Add a new agent field to the report
1. Add column to `CREATE_FINDINGS` in `db.py`
2. Add field to `insert_finding()` parameter dict in `db.py`
3. Populate the field in `agents/vuln.py` or `agents/exploit.py`
4. Reference it in the Gemini prompt in `agents/report.py`
5. Add to `pdf-template.ts` in the frontend

### Change the Gemini model
Edit one line in `backend/gemini_client.py`:
```python
MODEL = "gemini-flash-lite-latest"   # change this
```

### Add a new SSE log level
1. Add to `LogLevel` union in `frontend/src/types/index.ts`
2. Add colour entry to `LEVEL_CLASS` and `LEVEL_ICON` in `LogFeed.tsx`
3. Add CSS rule in `LogFeed.module.css`

### Test the SSE stream without running a full scan
```bash
curl -N http://localhost:8000/scan/<session-id>/stream
```

### Reset the database between demo runs
```bash
rm backend/arta.db && uvicorn main:app --port 8000 --reload
```

---

## What ARTA Will NOT Do
- Scan targets you don't own (the auth checkbox is enforced in the API as a hard 403)
- Exfiltrate data outside the sandbox subprocess
- Install packages inside PoC scripts (stdlib only, enforced by the sandbox env)
- Retain any session data after `arta.db` is deleted
