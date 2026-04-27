"""
agents/recon.py — Reconnaissance agent.

1. Runs nmap against the target.
2. Sends the XML output to Gemini for structured parsing.
3. Writes recon.json and persists to SQLite.
"""

import asyncio
import json
import time
from pathlib import Path

import db
import events
import gemini_client as gemini
from tools.nmap_runner import run_nmap


async def run(
    session_id: str,
    target_ip: str,
    session_dir: Path,
    scan_depth: str,
) -> dict:
    """
    Returns structured recon data:
    { "target": str, "open_ports": [...], "os_guess": str }
    """
    await events.emit(session_id, "recon", "info", "RECON_STARTED",
                      payload={"target": target_ip})

    full_scan = (scan_depth == "full")
    
    await events.emit(session_id, "recon", "tool", "NMAP_LAUNCHED",
                      tool="nmap", payload={"depth": scan_depth, "all_ports": full_scan})

    session = await db.get_session(session_id)
    attacker = None
    if session and session.get("attacker_ip"):
        attacker = {
            "ip": session.get("attacker_ip"),
            "username": session.get("attacker_user"),
            "password": session.get("attacker_pass"),
        }

    start      = time.monotonic()
    nmap_xml   = await asyncio.to_thread(run_nmap, target_ip, session_dir, full_scan=full_scan, attacker=attacker, session_id=session_id)
    duration_ms = int((time.monotonic() - start) * 1000)

    port_count = nmap_xml.count('<port protocol=')
    if port_count == 0:
        await events.emit(session_id, "recon", "warning",
                          "NO_PORTS_FOUND — Target might be offline, firewalled, or VPN is disconnected",
                          tool="nmap")

    await events.emit(session_id, "recon", "gemini",
                      "GEMINI_PARSING nmap XML output", tool="gemini_function_call")

    prompt = f"""
You are a penetration tester parsing nmap output.
Parse the following nmap XML and extract every open port and service.

Respond with this JSON structure:
{{
  "target": "{target_ip}",
  "os_guess": "<OS guess or 'Unknown'>",
  "open_ports": [
    {{
      "port": <int>,
      "protocol": "<tcp|udp>",
      "service": "<service name>",
      "version": "<detected version or empty string>",
      "extra_info": "<any banner or script output>"
    }}
  ]
}}

NMAP XML:
{nmap_xml[:30000]}
"""

    start       = time.monotonic()
    recon_data  = await gemini.ask_json(prompt)
    duration_ms = int((time.monotonic() - start) * 1000)

    recon_path = session_dir / "recon.json"
    recon_path.write_text(json.dumps(recon_data, indent=2))

    port_summary = ", ".join(
        f"{p['port']}/{p['service']}" for p in recon_data.get("open_ports", [])
    )
    await events.emit(
        session_id, "recon", "success",
        f"RECON_COMPLETE — {len(recon_data.get('open_ports', []))} services: {port_summary}",
        tool="gemini_function_call",
        duration_ms=duration_ms,
        payload=recon_data,
    )

    return recon_data
