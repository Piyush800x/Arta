"""
agents/report.py — Report agent.

Assembles every piece of data from the session and asks Gemini to
produce a comprehensive, structured pentest report JSON.

Report sections:
  - Meta + classification header
  - Executive summary with overall risk score
  - Methodology narrative
  - Detailed findings (CVSS vector breakdown, OWASP, CWE, evidence, remediation)
  - CVSS scoring table
  - Attack timeline
  - Exploitation results with evidence
  - Remediation runbook (prioritised, with exact commands and validation steps)
  - Risk heat map data (for frontend chart)
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

    session     = await db.get_session(session_id)
    all_findings = await db.get_findings(session_id)

    # Build the exploit results summary
    exploit_results = []
    for f in exploit_data:
        exploit_results.append({
            "cve_id":        f.get("cve_id"),
            "succeeded":     f.get("exploit_succeeded", False),
            "shell_access":  f.get("shell_access", False),
            "access_level":  f.get("access_level", "none"),
            "method":        f.get("method", ""),
            "evidence":      f.get("exploit_evidence", ""),
            "artifacts":     f.get("artifacts", ""),
            "evidence_excerpt": (f.get("evidence_stdout") or "")[:600],
        })

    report_input = {
        "session":         session,
        "target":          session.get("target_scope"),
        "os_guess":        recon_data.get("os_guess", "Unknown"),
        "open_ports":      recon_data.get("open_ports", []),
        "findings":        all_findings,
        "exploit_results": exploit_results,
        "total_findings":  len(all_findings),
        "critical_count":  session.get("critical_count", 0),
        "exploited_count": sum(1 for f in exploit_data if f.get("exploit_succeeded")),
        "shell_count":     sum(1 for f in exploit_data if f.get("shell_access")),
    }

    await events.emit(
        session_id, "report", "gemini",
        f"GEMINI_SYNTHESIZING — {len(all_findings)} findings, {report_input['exploited_count']} exploited",
        tool="gemini_function_call",
    )

    prompt = f"""
You are a senior penetration tester writing a professional, detailed report for a client.
This is a real lab exercise against an authorised target (Metasploitable 2).

FULL SESSION DATA:
{json.dumps(report_input, indent=2)[:12000]}

Produce a comprehensive JSON report matching this exact structure:

{{
  "meta": {{
    "session_id":      "{session_id}",
    "target":          "<IP>",
    "scan_date":       "<ISO date>",
    "scope":           "<in-scope hosts and services>",
    "classification":  "CONFIDENTIAL",
    "overall_risk":    "<CRITICAL|HIGH|MEDIUM|LOW>",
    "risk_score":      <int 0-100>,
    "risk_rationale":  "<2 sentences explaining the overall risk score>"
  }},

  "executive_summary": "<3-4 paragraph plain-English summary for a non-technical audience. Cover: what was tested, what was found, what was proven exploitable, and the business impact>",

  "methodology": {{
    "approach": "<paragraph describing the black-box approach>",
    "tools_used": ["nmap", "metasploit", "gemini-ai", "python-poc"],
    "phases": [
      {{ "phase": "Reconnaissance", "description": "<what was done>" }},
      {{ "phase": "Vulnerability Analysis", "description": "<what was done>" }},
      {{ "phase": "Exploitation",           "description": "<what was done>" }},
      {{ "phase": "Reporting",              "description": "<what was done>" }}
    ]
  }},

  "findings": [
    {{
      "cve_id":              "<CVE-YYYY-NNNN>",
      "title":               "<short descriptive title>",
      "severity":            "<critical|high|medium|low>",
      "cvss_v3":             <float>,
      "cvss_vector":         "<CVSS:3.x/AV:.../...>",
      "cvss_breakdown": {{
        "attack_vector":        "<Network|Adjacent|Local|Physical>",
        "attack_complexity":    "<Low|High>",
        "privileges_required":  "<None|Low|High>",
        "user_interaction":     "<None|Required>",
        "scope":                "<Unchanged|Changed>",
        "confidentiality":      "<None|Low|High>",
        "integrity":            "<None|Low|High>",
        "availability":         "<None|Low|High>"
      }},
      "affected_component":  "<service:port (version)>",
      "owasp_category":      "<e.g. A06:2021 – Vulnerable and Outdated Components>",
      "cwe":                 "<e.g. CWE-78 – OS Command Injection>",
      "description":         "<2-3 sentences describing the vulnerability clearly>",
      "technical_detail":    "<deeper technical explanation of how the flaw works>",
      "business_impact":     "<what this means for the organisation in plain terms>",
      "exploit_result": {{
        "attempted":     <true|false>,
        "succeeded":     <true|false>,
        "method":        "<metasploit|gemini_poc|none>",
        "access_level":  "<none|user|root>",
        "evidence":      "<what was observed — e.g. 'root shell obtained, /etc/shadow read'>",
        "artifacts":     "<any captured data — redact sensitive content>"
      }},
      "remediation": {{
        "short":    "<one-line fix>",
        "detail":   "<paragraph with full remediation steps>",
        "command":  "<exact shell command>",
        "package":  "<package name or null>",
        "validation": "<how to verify the fix was applied successfully>"
      }},
      "references": ["<url1>", "<url2>"]
    }}
  ],

  "cvss_table": [
    {{ "cve_id": "<id>", "title": "<short title>", "cvss_v3": <float>, "severity": "<label>", "exploited": <bool> }}
  ],

  "risk_heatmap": [
    {{ "severity": "<label>", "likelihood": "<low|medium|high>", "impact": "<low|medium|high>", "count": <int> }}
  ],

  "attack_timeline": [
    {{ "time_offset": "<+0:00>", "agent": "<agent>", "action": "<description>", "outcome": "<outcome>" }}
  ],

  "exploitation_summary": {{
    "total_attempted":  <int>,
    "total_succeeded":  <int>,
    "shell_access":     <int>,
    "highest_access":   "<none|user|root>",
    "narrative":        "<paragraph describing what an attacker could have done with this access>"
  }},

  "remediation_runbook": [
    {{
      "priority":    <int starting at 1>,
      "cve_id":      "<id>",
      "severity":    "<label>",
      "fix_summary": "<one line>",
      "steps": [
        "<step 1>",
        "<step 2>"
      ],
      "command":     "<primary shell command>",
      "validation":  "<how to confirm the fix>",
      "estimated_effort": "<e.g. 30 minutes>"
    }}
  ],

  "conclusion": "<2 paragraphs: summary of posture + recommended next steps>"
}}
"""

    start      = time.monotonic()
    report_json = await gemini.ask_json(prompt)
    duration_ms = int((time.monotonic() - start) * 1000)

    report_path = session_dir / "report.json"
    report_path.write_text(json.dumps(report_json, indent=2))
    await db.update_session(session_id, report_json_path=str(report_path))

    await events.emit(
        session_id, "report", "info",
        f"REPORT_JSON_READY — risk_score={report_json.get('meta', {}).get('risk_score', '?')}",
        tool="gemini_function_call",
        duration_ms=duration_ms,
    )

    pdf_url = f"/api/report/{session_id}/pdf"
    await events.emit(
        session_id, "report", "success",
        "PDF_READY",
        payload={
            "pdf_url":          pdf_url,
            "report_json_path": str(report_path),
            "risk_score":       report_json.get("meta", {}).get("risk_score"),
            "overall_risk":     report_json.get("meta", {}).get("overall_risk"),
        },
    )
