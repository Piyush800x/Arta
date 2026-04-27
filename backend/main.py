"""
main.py — FastAPI application.

Endpoints:
  POST /scan              — Start a new scan session
  GET  /scan/{id}/stream  — SSE log stream for a session
  GET  /scan/{id}         — Session status + findings summary
  GET  /report/{id}       — Full report JSON (fetched by Next.js PDF renderer)
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
from tools.cve_lookup import load_exploitdb


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    load_exploitdb()    # loads ExploitDB CSV into memory (optional)
    yield


app = FastAPI(title="ARTA Backend", version="2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_session_queues: dict[str, asyncio.Queue] = {}


class ScanRequest(BaseModel):
    target_ip:  str
    scan_depth: str  = "standard"
    authorised: bool
    attacker_ip:   str | None = None
    attacker_user: str | None = None
    attacker_pass: str | None = None


class ScanResponse(BaseModel):
    session_id: str
    status:     str
    stream_url: str


class ReScanRequest(BaseModel):
    finding_id: str
    target_ip:  str
    port:       int
    service:    str


@app.post("/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest):
    if not req.authorised:
        raise HTTPException(
            status_code=403,
            detail="Authorisation checkbox must be confirmed before scanning."
        )

    session_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    await db.create_session({
        "id":           session_id,
        "target_scope": req.target_ip,
        "scan_depth":   req.scan_depth,
        "status":       "pending",
        "created_at":   now,
        "attacker_ip":   req.attacker_ip,
        "attacker_user": req.attacker_user,
        "attacker_pass": req.attacker_pass,
    })

    queue: asyncio.Queue = asyncio.Queue()
    _session_queues[session_id] = queue
    events.set_queue(queue)

    asyncio.create_task(
        orchestrator.run(session_id, req.target_ip, req.scan_depth)
    )

    return ScanResponse(
        session_id = session_id,
        status     = "started",
        stream_url = f"/scan/{session_id}/stream",
    )


@app.get("/scan/{session_id}/stream")
async def stream_logs(session_id: str):
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    async def event_generator():
        past_logs = await db.get_recent_logs(session_id, limit=200)
        for log in past_logs:
            yield _format_sse(log)

        queue = _session_queues.get(session_id)
        if queue is None:
            return

        terminal_statuses = {"complete", "error"}
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                yield _format_sse(event)
                current = await db.get_session(session_id)
                if current and current.get("status") in terminal_statuses:
                    break
            except asyncio.TimeoutError:
                yield ": ping\n\n"

        _session_queues.pop(session_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": FRONTEND_URL,
        },
    )


@app.get("/scan/{session_id}")
async def get_session(session_id: str):
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    findings = await db.get_findings(session_id)
    return {"session": session, "findings": findings}


@app.get("/report/{session_id}")
async def get_report(session_id: str):
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    report_path = session.get("report_json_path")
    if not report_path or not Path(report_path).exists():
        raise HTTPException(status_code=404, detail="Report not yet generated")
    return json.loads(Path(report_path).read_text())


@app.post("/rescan")
async def rescan_finding(req: ReScanRequest):
    """Re-run nmap against a single port to verify a fix."""
    from tools.nmap_runner import run_nmap
    import tempfile

    session_dir = Path(tempfile.mkdtemp())
    xml = await asyncio.to_thread(
        run_nmap, req.target_ip, session_dir, full_scan=False
    )
    # Check if the port still shows the same service/version
    still_open = f'portid="{req.port}"' in xml
    status = "still_vulnerable" if still_open else "verified_fixed"

    await db.update_finding_status(req.finding_id, status)
    return {"finding_id": req.finding_id, "status": status, "nmap_xml": xml[:2000]}


def _format_sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"
