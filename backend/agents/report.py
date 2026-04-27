"""
agents/report.py — Report agent.

1. Assembles all findings from SQLite + session files.
2. Sends everything to Gemini for professional report synthesis.
3. Writes report.json for the Next.js PDF renderer.
4. Emits PDF_READY with the download URL as the final SSE event.
"""

import json
import time
from pathlib import Path

import db
import events
import gemini_client as gemini


async def run(
    session_id: str,
    recon_data: dict,
    vuln_data: list[dict],
    exploit_data: list[dict],
    session_dir: Path,
) -> None:
    await events.emit(session_id, "report", "info", "REPORT_STARTED")

    # ── Assemble all data ─────────────────────────────────────────────
    session = await db.get_session(session_id)
    all_findings = await db.get_findings(session_id)

    report_input = {
        "session":   session,
        "recon":     recon_data,
        "findings":  all_findings,
        "exploits":  [
            {
                "cve_id":           f.get("cve_id"),
                "succeeded":        f.get("exploit_succeeded"),
                "shell_access":     "uid=0" in (f.get("evidence_stdout") or ""),
                "evidence_excerpt": (f.get("evidence_stdout") or "")[:500],
            }
            for f in exploit_data
        ],
    }

    # ── Gemini: synthesise the full report ────────────────────────────
    await events.emit(session_id, "report", "gemini",
                      "GEMINI_SYNTHESIZING full pentest report",
                      tool="gemini_function_call")

    prompt = f"""
You are a senior penetration tester writing a professional report for a client.
Use the following scan data to produce a complete, structured pentest report.

SCAN DATA:
{json.dumps(report_input, indent=2)[:10000]}

Respond with a JSON object matching this structure exactly:
{{
  "meta": {{
    "session_id": "{session_id}",
    "target":     "<target IP>",
    "scan_date":  "<ISO date>",
    "scope":      "<scope description>",
    "classification": "CONFIDENTIAL"
  }},
  "executive_summary": "<2-3 paragraph plain-English overview for a non-technical audience>",
  "methodology": "<brief paragraph on the tools and approach used>",
  "findings": [
    {{
      "cve_id":       "<CVE-YYYY-NNNN>",
      "title":        "<short descriptive title>",
      "severity":     "<critical|high|medium|low>",
      "cvss_v3":      <float>,
      "affected":     "<service:port>",
      "description":  "<paragraph describing the vulnerability>",
      "evidence":     "<what was observed — redacted PoC output>",
      "owasp":        "<OWASP category>",
      "remediation":  "<specific fix with command>"
    }}
  ],
  "cvss_table": [
    {{ "cve_id": "<id>", "cvss_v3": <float>, "severity": "<label>" }}
  ],
  "attack_timeline": [
    {{ "time": "<relative time>", "agent": "<agent>", "action": "<description>" }}
  ],
  "remediation_runbook": [
    {{
      "priority":    <int>,
      "cve_id":      "<id>",
      "fix":         "<specific fix>",
      "command":     "<shell command>",
      "validation":  "<how to verify the fix worked>"
    }}
  ]
}}
"""

    start = time.monotonic()
    report_json = await gemini.ask_json(prompt)
    duration_ms = int((time.monotonic() - start) * 1000)

    # ── Write report.json ─────────────────────────────────────────────
    report_path = session_dir / "report.json"
    report_path.write_text(json.dumps(report_json, indent=2))

    await db.update_session(session_id, report_json_path=str(report_path))

    await events.emit(session_id, "report", "info", "REPORT_JSON_READY",
                      tool="gemini_function_call", duration_ms=duration_ms)

    # ── Signal the frontend to trigger PDF rendering ──────────────────
    pdf_url = f"/api/report/{session_id}/pdf"
    await events.emit(
        session_id, "report", "success", "PDF_READY",
        payload={"pdf_url": pdf_url, "report_json_path": str(report_path)},
    )
