"""
agents/vuln.py — Vulnerability Analysis agent.

1. CPE-matches each discovered service against the local NVD index.
2. Sends candidate CVEs to Gemini for contextual ranking.
3. Checks ExploitDB for exploit availability.
4. Persists findings to SQLite.
"""

import json
import uuid
import time
from pathlib import Path

import db
import events
import gemini_client as gemini
from tools.cve_lookup import search_by_product, check_exploitdb

# CVSS score → severity label
_SEVERITY = {
    (9.0, 10.0): "critical",
    (7.0,  8.9): "high",
    (4.0,  6.9): "medium",
    (0.1,  3.9): "low",
}


def _severity_label(cvss: float) -> str:
    for (lo, hi), label in _SEVERITY.items():
        if lo <= cvss <= hi:
            return label
    return "info"


async def run(session_id: str, recon_data: dict, session_dir: Path) -> list[dict]:
    """
    Returns a list of ranked finding dicts ready for the exploit agent.
    """
    await events.emit(session_id, "vuln", "info", "VULN_ANALYSIS_STARTED")

    all_candidates: list[dict] = []

    # ── Step 1: CPE match each service ───────────────────────────────
    for port_info in recon_data.get("open_ports", []):
        service = port_info.get("service", "")
        version = port_info.get("version", "")
        if not service:
            continue

        candidates = search_by_product(service, version, limit=20)
        if candidates:
            await events.emit(
                session_id, "vuln", "info",
                f"CPE_MATCH_FOUND — {service} {version}: {len(candidates)} candidate CVE(s)",
                payload={"service": service, "version": version, "count": len(candidates)},
            )
            for c in candidates:
                c["affected_service"] = service
                c["affected_port"]    = port_info.get("port")
                c["detected_version"] = version
            all_candidates.extend(candidates)

    if not all_candidates:
        await events.emit(session_id, "vuln", "warning",
                          "No CVE candidates found via CPE matching")
        return []

    # ── Step 2: Gemini ranks by exploitability in this context ───────
    await events.emit(session_id, "vuln", "gemini",
                      f"GEMINI_RANKING {len(all_candidates)} CVE candidate(s)",
                      tool="gemini_function_call")

    prompt = f"""
You are a penetration tester prioritising CVEs for a live target.
Target recon context: {json.dumps(recon_data, indent=2)}

CVE candidates: {json.dumps(all_candidates[:20], indent=2)}

Rank these CVEs by exploitability in this specific context.
Return a JSON array of the top 5 findings:
[
  {{
    "cve_id": "<CVE-YYYY-NNNN>",
    "cvss_v3": <float>,
    "severity": "<critical|high|medium|low>",
    "affected_service": "<service name>",
    "affected_port": <int>,
    "detected_version": "<version string>",
    "exploit_available": <true|false>,
    "msf_module": "<module path or null>",
    "reason": "<1-sentence explanation of why this is ranked here>",
    "owasp_category": "<e.g. A06:2021 – Vulnerable Components>",
    "remediation_short": "<one-line fix>",
    "remediation_package": "<package to upgrade or null>",
    "remediation_cmd": "<exact shell command to apply fix>"
  }}
]
"""
    start = time.monotonic()
    ranked: list[dict] = await gemini.ask_json(prompt)
    duration_ms = int((time.monotonic() - start) * 1000)

    # ── Step 3: Check ExploitDB and persist each finding ─────────────
    findings = []
    critical_count = 0

    for item in ranked:
        edb = check_exploitdb(item.get("cve_id", ""))
        exploit_source = "metasploit" if item.get("msf_module") else \
                         ("exploitdb" if edb else "none")

        finding = {
            "id":                  str(uuid.uuid4()),
            "session_id":          session_id,
            "cve_id":              item.get("cve_id"),
            "cvss_v3":             item.get("cvss_v3", 0.0),
            "severity":            item.get("severity", _severity_label(item.get("cvss_v3", 0))),
            "affected_service":    item.get("affected_service"),
            "affected_port":       item.get("affected_port"),
            "detected_version":    item.get("detected_version"),
            "exploit_available":   item.get("exploit_available", bool(edb)),
            "exploit_source":      exploit_source,
            "exploit_succeeded":   False,
            "evidence_stdout":     None,
            "owasp_category":      item.get("owasp_category"),
            "remediation_short":   item.get("remediation_short"),
            "remediation_package": item.get("remediation_package"),
            "remediation_cmd":     item.get("remediation_cmd"),
            # Extra fields for exploit agent (not in DB schema)
            "msf_module":          item.get("msf_module"),
            "reason":              item.get("reason"),
        }
        await db.insert_finding(finding)
        findings.append(finding)

        if finding["severity"] == "critical":
            critical_count += 1

    # Write to file for report agent
    vulns_path = session_dir / "vulns.json"
    vulns_path.write_text(json.dumps(findings, indent=2))

    await db.update_session(session_id, finding_count=len(findings),
                            critical_count=critical_count)

    severity_summary = {s: sum(1 for f in findings if f["severity"] == s)
                        for s in ("critical", "high", "medium", "low")}
    await events.emit(
        session_id, "vuln", "success",
        f"VULN_COMPLETE — {len(findings)} finding(s): {severity_summary}",
        tool="gemini_function_call",
        duration_ms=duration_ms,
        payload={"findings": len(findings), "by_severity": severity_summary},
    )

    return findings
