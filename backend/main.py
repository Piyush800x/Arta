"""
main.py — FastAPI application.

Endpoints:
  POST /scan              — Start a new scan session
  GET  /scan/{id}/stream  — SSE log stream for a session
  GET  /scan/{id}         — Session status + findings summary
  GET  /report/{id}       — Full report JSON (fetched by Next.js PDF renderer)

The SSE stream is the core of the demo: every agent action streams
here in real time, colour-coded and rendered by the Next.js frontend.
"""

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import db
import events
from agents import orchestrator
from config import FRONTEND_URL, SESSIONS_TMP
from tools.cve_lookup import load_data


# ── Lifespan: init DB and load local data files on startup ────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    load_data()        # loads NVD JSON + ExploitDB CSV into memory
    yield


app = FastAPI(title="ARTA Backend", version="2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# One global queue per active session: session_id → asyncio.Queue
_session_queues: dict[str, asyncio.Queue] = {}


# ── Request / response models ─────────────────────────────────────────

class ScanRequest(BaseModel):
    target_ip:       str
    scan_depth:      str = "standard"   # "standard" | "full"
    authorised:      bool               # must be True to start scan


class ScanResponse(BaseModel):
    session_id: str
    status:     str
    stream_url: str


# ── POST /scan ────────────────────────────────────────────────────────

@app.post("/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest):
    if not req.authorised:
        raise HTTPException(
            status_code=403,
            detail="Authorisation checkbox must be confirmed before scanning."
        )

    session_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Create DB record
    await db.create_session({
        "id":           session_id,
        "target_scope": req.target_ip,
        "scan_depth":   req.scan_depth,
        "status":       "pending",
        "created_at":   now,
    })

    # Create per-session asyncio queue and wire it to the event system
    queue: asyncio.Queue = asyncio.Queue()
    _session_queues[session_id] = queue
    events.set_queue(queue)

    # Launch the full agent chain in the background
    asyncio.create_task(
        orchestrator.run(session_id, req.target_ip, req.scan_depth)
    )

    return ScanResponse(
        session_id = session_id,
        status     = "started",
        stream_url = f"/scan/{session_id}/stream",
    )


# ── GET /scan/{id}/stream — SSE ───────────────────────────────────────

@app.get("/scan/{session_id}/stream")
async def stream_logs(session_id: str):
    """
    Server-Sent Events endpoint.
    - Replays the last 50 persisted events for reconnect support.
    - Then streams live events from the asyncio queue until the session ends.
    """
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    async def event_generator():
        # Replay buffered events (SSE reconnect support)
        past_logs = await db.get_recent_logs(session_id, limit=50)
        for log in past_logs:
            yield _format_sse(log)

        # Stream live events
        queue = _session_queues.get(session_id)
        if queue is None:
            return

        terminal_statuses = {"complete", "error"}
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                yield _format_sse(event)

                # Stop streaming when the session is done
                current = await db.get_session(session_id)
                if current and current.get("status") in terminal_statuses:
                    break

            except asyncio.TimeoutError:
                # Keep-alive ping so the connection doesn't drop
                yield ": ping\n\n"

        # Clean up queue
        _session_queues.pop(session_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",   # disable nginx buffering
            "Access-Control-Allow-Origin": FRONTEND_URL,
        },
    )


# ── GET /scan/{id} — session summary ─────────────────────────────────

@app.get("/scan/{session_id}")
async def get_session(session_id: str):
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    findings = await db.get_findings(session_id)
    return {"session": session, "findings": findings}


# ── GET /report/{id} — full report JSON ──────────────────────────────

@app.get("/report/{session_id}")
async def get_report(session_id: str):
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    report_path = session.get("report_json_path")
    if not report_path or not Path(report_path).exists():
        raise HTTPException(status_code=404, detail="Report not yet generated")

    return json.loads(Path(report_path).read_text(encoding="utf-8"))


# ── Helpers ───────────────────────────────────────────────────────────

def _format_sse(event: dict) -> str:
    """Serialise a log event dict into the SSE wire format."""
    return f"data: {json.dumps(event)}\n\n"
