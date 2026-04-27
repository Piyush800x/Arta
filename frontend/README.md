# ARTA Frontend — Next.js 14

**Autonomous Red Team Agent v2.0 | Bot to Agent Hackathon | IEM Kolkata | 27 April 2026**

Live scan dashboard with real-time SSE log streaming, agent stepper, findings table,
and in-browser PDF report viewer.

---

## Prerequisites

- Node.js 18+
- ARTA backend running on `http://localhost:8000`
- Puppeteer / Chrome (installed automatically via `npm install`)

---

## Setup

```bash
cd arta-frontend

# Install dependencies (also downloads headless Chrome for Puppeteer ~170MB)
npm install

# Copy and fill in env
cp .env.local.example .env.local
# Edit if your backend is on a different port
```

`.env.local`:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## Run

```bash
# Development (with hot reload)
npm run dev
```

Open **http://localhost:3000** in your browser.

---

## Pages & Routes

| Route | Description |
|-------|-------------|
| `/` | Scan submission form — enter target IP, depth, auth checkbox |
| `/scan/[id]` | Live dashboard — SSE log stream, agent stepper, findings table, PDF viewer |
| `POST /api/scan` | Proxies scan request to FastAPI backend |
| `GET /api/scan/[id]/stream` | SSE proxy — pipes backend stream to browser |
| `GET /api/report/[id]/pdf` | Fetches report JSON → renders HTML → Puppeteer PDF |

---

## Architecture

```
Browser
  │
  ├── GET /scan/{id}           → SSE log stream via EventSource
  │     └── /api/scan/[id]/stream  (Next.js proxies FastAPI SSE)
  │
  ├── POST /api/scan           → Proxied to FastAPI POST /scan
  │
  └── GET /api/report/[id]/pdf → Next.js fetches report JSON
                                  → builds HTML template
                                  → Puppeteer renders PDF
                                  → returns binary to browser
```

---

## Design System

**Theme**: Terminal-noir — phosphor green on deep black, monospace typography.

| Token | Value |
|-------|-------|
| `--green` | `#00ff41` — primary accent |
| `--black` | `#080a0c` — base background |
| `--font-mono` | IBM Plex Mono |
| `--font-display` | Space Mono |

Log level colour coding matches the PRD spec:

| Level | Colour | Used for |
|-------|--------|----------|
| `info` | Gray | Standard agent status |
| `gemini` | Purple | Every Gemini API call |
| `success` | Green | Completed steps, exploits landed |
| `warning` | Amber | Partial results, retries |
| `error` | Red | Tool failures, errors |
| `tool` | Blue | Raw tool output excerpts |

---

## Project Structure

```
arta-frontend/
├── src/
│   ├── app/
│   │   ├── layout.tsx              # Root layout + global CSS
│   │   ├── globals.css             # Design tokens + animations
│   │   ├── page.tsx                # Landing / scan form
│   │   ├── page.module.css
│   │   ├── scan/[id]/
│   │   │   ├── page.tsx            # Live scan dashboard
│   │   │   └── page.module.css
│   │   └── api/
│   │       ├── scan/route.ts           # POST — start scan
│   │       ├── scan/[id]/stream/route.ts  # GET — SSE proxy
│   │       └── report/[id]/pdf/route.ts   # GET — PDF render
│   ├── components/
│   │   ├── AgentStepper.tsx        # Recon→Vuln→Exploit→Report status bar
│   │   ├── AgentStepper.module.css
│   │   ├── LogFeed.tsx             # Colour-coded SSE log rows
│   │   ├── LogFeed.module.css
│   │   ├── FindingsTable.tsx       # CVE findings table
│   │   ├── FindingsTable.module.css
│   │   ├── ReportViewer.tsx        # iframe PDF preview + download
│   │   └── ReportViewer.module.css
│   ├── lib/
│   │   ├── api.ts                  # Typed API client
│   │   └── pdf-template.ts         # HTML template for Puppeteer
│   └── types/
│       └── index.ts                # Shared TypeScript types
├── next.config.js
├── tsconfig.json
├── package.json
└── .env.local.example
```

---

## Demo Tips

- Start the Python backend first: `uvicorn main:app --port 8000`
- Then start Next.js: `npm run dev`
- Open `http://localhost:3000` — enter Metasploitable IP — click **Launch ARTA**
- The `/scan/{id}` page auto-navigates and begins streaming immediately
- When `PDF_READY` fires, the report viewer slides in on the right panel
- Click **↓ Download PDF** to save the pentest report

---

## Fallback if Puppeteer fails at venue

The PDF route (`/api/report/[id]/pdf`) will return a 500 with a clear error message.
The raw report JSON is always accessible at `GET http://localhost:8000/report/{id}` —
paste it into a browser tab or serve the HTML template directly as a fallback.
