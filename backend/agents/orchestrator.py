"""
agents/orchestrator.py — Mission planner.

Accepts the scan request, asks Gemini to decompose the target into a
task plan, then fires each agent in sequence via asyncio.Queue.
"""

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

import db
import events
import gemini_client as gemini
from agents import recon, vuln, exploit, report
from config import SESSIONS_TMP


async def run(session_id: str, target_ip: str, scan_depth: str) -> None:
    """
    Entry point called by FastAPI when a scan starts.
    Runs the full agent chain: Recon → Vuln → Exploit → Report.
    """
    session_dir = Path(SESSIONS_TMP) / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    await events.emit(session_id, "orchestrator", "info", "SESSION_STARTED",
                      payload={"target": target_ip, "scan_depth": scan_depth})

    await db.update_session(session_id, status="recon")

    # ── Step 1: Decompose mission with Gemini ─────────────────────────
    plan = await _plan_mission(session_id, target_ip, scan_depth)
    await events.emit(session_id, "orchestrator", "gemini",
                      f"Mission plan: {plan.get('estimated_duration', 'N/A')} estimated",
                      payload=plan)

    # ── Step 2: Run agents in sequence ────────────────────────────────
    try:
        recon_data = await recon.run(session_id, target_ip, session_dir, scan_depth)

        await db.update_session(session_id, status="vuln_analysis")
        vuln_data = await vuln.run(session_id, recon_data, session_dir)

        await db.update_session(session_id, status="exploiting")
        exploit_data = await exploit.run(session_id, vuln_data, target_ip, session_dir)

        await db.update_session(session_id, status="reporting")
        await report.run(session_id, recon_data, vuln_data, exploit_data, session_dir)

        await db.update_session(
            session_id,
            status="complete",
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        await events.emit(session_id, "orchestrator", "success", "ALL_AGENTS_COMPLETE")

    except Exception as exc:
        await events.emit(session_id, "orchestrator", "error",
                          f"SESSION_ERROR: {exc}", payload={"error": str(exc)})
        await db.update_session(session_id, status="error",
                                completed_at=datetime.now(timezone.utc).isoformat())


async def _plan_mission(session_id: str, target_ip: str, scan_depth: str) -> dict:
    prompt = f"""
You are a penetration testing orchestrator.
Target IP: {target_ip}
Scan depth: {scan_depth}

Respond with a JSON object:
{{
  "scan_depth": "{scan_depth}",
  "agent_sequence": ["recon", "vuln", "exploit", "report"],
  "estimated_duration": "<human-readable estimate e.g. '8-12 minutes'>",
  "notes": "<any special considerations for this target>"
}}
"""
    try:
        return await gemini.ask_json(prompt)
    except Exception:
        # Fallback plan if Gemini is unavailable
        return {
            "scan_depth":       scan_depth,
            "agent_sequence":   ["recon", "vuln", "exploit", "report"],
            "estimated_duration": "8-15 minutes",
            "notes":            "Default plan (Gemini unavailable)",
        }
