"""
agents/vuln.py — Vulnerability Analysis agent.

1. Queries the live NVD API for each discovered service/version.
2. Sends candidate CVEs to Gemini for contextual ranking + OWASP mapping.
3. Checks ExploitDB for exploit availability.
4. Persists enriched findings to SQLite.
"""

import json
import uuid
import time
from pathlib import Path

import db
import events
import gemini_client as gemini
from tools.cve_lookup import search_by_product, check_exploitdb
from tools.metasploitable_kb import match_kb_findings


async def run(session_id: str, recon_data: dict, session_dir: Path) -> list[dict]:
    """
    Returns a list of enriched finding dicts ready for the exploit agent.
    """
    await events.emit(session_id, "vuln", "info", "VULN_ANALYSIS_STARTED")

    open_ports  = recon_data.get("open_ports", [])
    all_candidates: list[dict] = []

    # ── Step 1a: Inject Metasploitable 2 KB findings (always reliable) ──
    kb_cve_ids: set[str] = set()
    for port_info in open_ports:
        service = port_info.get("service", "")
        version = port_info.get("version", "")
        port    = port_info.get("port")
        if not service:
            continue

        kb_hits = match_kb_findings(service, port, version)
        for hit in kb_hits:
            if hit["cve_id"] not in kb_cve_ids:
                kb_cve_ids.add(hit["cve_id"])
                hit["affected_service"] = service
                hit["affected_port"]    = port
                hit["detected_version"] = version
                all_candidates.append(hit)

        if kb_hits:
            await events.emit(
                session_id, "vuln", "info",
                f"KB_MATCH — {service}:{port}: {len(kb_hits)} known vuln(s) injected",
                payload={"service": service, "kb_cves": [h["cve_id"] for h in kb_hits]},
            )

    # ── Step 1b: Live NVD API query for each service ──────────────────
    for port_info in open_ports:
        service = port_info.get("service", "")
        version = port_info.get("version", "")
        if not service:
            continue

        await events.emit(
            session_id, "vuln", "tool",
            f"NVD_QUERY — {service} {version}",
            tool="nvd_api",
            payload={"service": service, "version": version},
        )

        candidates = await search_by_product(service, version, limit=10)

        if candidates:
            await events.emit(
                session_id, "vuln", "info",
                f"NVD_RESULTS — {service} {version}: {len(candidates)} CVE(s) found",
                payload={"service": service, "count": len(candidates),
                         "top_cvss": candidates[0]["cvss_v3"] if candidates else 0},
            )
            for c in candidates:
                c["affected_service"] = service
                c["affected_port"]    = port_info.get("port")
                c["detected_version"] = version
            all_candidates.extend(candidates)
        else:
            await events.emit(
                session_id, "vuln", "warning",
                f"NVD_NO_RESULTS — {service} {version}",
            )

    if not all_candidates:
        await events.emit(session_id, "vuln", "warning",
                          "No CVE candidates found — target may be fully patched")
        return []

    # ── Step 2: Gemini ranks by exploitability in this exact context ──
    # Deduplicate and take top 30 by CVSS before sending to Gemini
    seen_ids: set[str] = set()
    unique_candidates  = []
    for c in sorted(all_candidates, key=lambda x: x["cvss_v3"], reverse=True):
        if c["cve_id"] not in seen_ids:
            seen_ids.add(c["cve_id"])
            unique_candidates.append(c)
        if len(unique_candidates) >= 30:
            break

    await events.emit(
        session_id, "vuln", "gemini",
        f"GEMINI_RANKING {len(unique_candidates)} unique CVE(s) by exploitability",
        tool="gemini_function_call",
    )

    prompt = f"""
You are a senior penetration tester prioritising CVEs for a live target.

TARGET CONTEXT:
{json.dumps(recon_data, indent=2)}

CVE CANDIDATES (from NVD):
{json.dumps(unique_candidates, indent=2)}

Rank these by how exploitable they are AGAINST THIS SPECIFIC TARGET right now.
Consider: service version match, network exposure, exploit maturity, chaining potential.

Return a JSON array of all the exploitable findings from the candidates provided:
[
  {{
    "cve_id":              "<CVE-YYYY-NNNN>",
    "cvss_v3":             <float>,
    "cvss_vector":         "<CVSS:3.x/AV:.../...>",
    "severity":            "<critical|high|medium|low>",
    "affected_service":    "<service name>",
    "affected_port":       <int>,
    "detected_version":    "<version string>",
    "description":         "<clear 1-2 sentence description of the flaw>",
    "exploit_available":   <true|false>,
    "msf_module":          "<metasploit module path or null>",
    "exploit_complexity":  "<low|medium|high>",
    "attack_vector":       "<network|adjacent|local|physical>",
    "privileges_required": "<none|low|high>",
    "user_interaction":    "<none|required>",
    "owasp_category":      "<e.g. A06:2021 – Vulnerable and Outdated Components>",
    "cwe":                 "<e.g. CWE-78>",
    "impact":              "<what an attacker gains if this lands>",
    "ranking_reason":      "<1 sentence on why this is ranked here>",
    "remediation_short":   "<one-line fix>",
    "remediation_package": "<package to upgrade or null>",
    "remediation_cmd":     "<exact shell command to apply the fix>",
    "references":          ["<url1>", "<url2>"]
  }}
]
"""

    start      = time.monotonic()
    ranked: list[dict] = await gemini.ask_json(prompt)
    duration_ms = int((time.monotonic() - start) * 1000)

    # ── Step 3: Check ExploitDB, persist each finding ─────────────────
    findings     = []
    critical_count = 0

    for item in ranked:
        cve_id = item.get("cve_id", "")
        edb    = check_exploitdb(cve_id)
        exploit_source = (
            "metasploit" if item.get("msf_module") else
            "exploitdb"  if edb else
            "none"
        )

        finding = {
            "id":                   str(uuid.uuid4()),
            "session_id":           session_id,
            "cve_id":               cve_id,
            "cvss_v3":              item.get("cvss_v3", 0.0),
            "cvss_vector":          item.get("cvss_vector", ""),
            "severity":             item.get("severity", "info"),
            "affected_service":     item.get("affected_service", ""),
            "affected_port":        item.get("affected_port"),
            "detected_version":     item.get("detected_version", ""),
            "description":          item.get("description", ""),
            "exploit_available":    item.get("exploit_available", bool(edb)),
            "exploit_complexity":   item.get("exploit_complexity", ""),
            "attack_vector":        item.get("attack_vector", ""),
            "privileges_required":  item.get("privileges_required", ""),
            "user_interaction":     item.get("user_interaction", ""),
            "exploit_source":       exploit_source,
            "exploit_succeeded":    False,
            "evidence_stdout":      None,
            "owasp_category":       item.get("owasp_category", ""),
            "cwe":                  item.get("cwe", ""),
            "impact":               item.get("impact", ""),
            "ranking_reason":       item.get("ranking_reason", ""),
            "owasp_category":       item.get("owasp_category", ""),
            "remediation_short":    item.get("remediation_short", ""),
            "remediation_package":  item.get("remediation_package"),
            "remediation_cmd":      item.get("remediation_cmd", ""),
            "references":           json.dumps(item.get("references", [])),
            # exploit agent needs these — not stored in DB
            "msf_module":           item.get("msf_module"),
        }

        await db.insert_finding(finding)
        findings.append(finding)
        if finding["severity"] == "critical":
            critical_count += 1

    # Write findings file for report agent
    vulns_path = session_dir / "vulns.json"
    vulns_path.write_text(json.dumps(findings, indent=2))

    await db.update_session(session_id,
                            finding_count=len(findings),
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
