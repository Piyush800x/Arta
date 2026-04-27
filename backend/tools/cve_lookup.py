"""
tools/cve_lookup.py — Live CVE lookup via NVD REST API v2.

Queries https://services.nvd.nist.gov/rest/json/cves/2.0 in real time.
Falls back to ExploitDB CSV (local) for exploit availability checks.

No API key is required for NVD. Rate limit: 5 req/30s unauthenticated.
We stay well within that with the built-in delay.
"""

import asyncio
import time
import httpx
from pathlib import Path
from typing import Optional

import pandas as pd
from config import EXPLOITDB_CSV, NVD_API_KEY

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_DELAY = 6.5   # seconds between NVD calls (safe for unauthenticated)

# ── ExploitDB loaded once at startup ─────────────────────────────────
_exploitdb: Optional[pd.DataFrame] = None


def load_exploitdb() -> None:
    """Load ExploitDB CSV into memory (optional but fast for exploit checks)."""
    global _exploitdb
    edb_path = Path(EXPLOITDB_CSV)
    if edb_path.exists():
        _exploitdb = pd.read_csv(edb_path, low_memory=False)
        print(f"[cve_lookup] Loaded {len(_exploitdb):,} ExploitDB entries.")
    else:
        print("[cve_lookup] ExploitDB CSV not found — exploit checks will use NVD only.")


# ── Live NVD API search ───────────────────────────────────────────────

async def search_by_product(product: str, version: str, limit: int = 10) -> list[dict]:
    """
    Query the NVD API for CVEs matching a product + version keyword.

    Returns a list of dicts with cve_id, cvss_v3, severity, description,
    cvss_vector, cwe, references.
    """
    await asyncio.sleep(_REQUEST_DELAY)

    keyword = f"{product} {version}".strip()
    params  = {
        "keywordSearch":  keyword,
        "resultsPerPage": limit,
        "startIndex":     0,
    }

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY    # optional — raises rate limit to 50 req/30s

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(NVD_BASE, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        print(f"[cve_lookup] NVD API error for '{keyword}': {exc}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve   = item.get("cve", {})
        cve_id = cve.get("id", "")

        # CVSS v3 score
        metrics  = cve.get("metrics", {})
        cvss_v3  = 0.0
        vector   = ""
        severity = "info"
        cvss_data_list = (
            metrics.get("cvssMetricV31", []) or
            metrics.get("cvssMetricV30", [])
        )
        if cvss_data_list:
            cvss_data = cvss_data_list[0].get("cvssData", {})
            cvss_v3   = cvss_data.get("baseScore", 0.0)
            vector    = cvss_data.get("vectorString", "")
            severity  = cvss_data_list[0].get("baseSeverity", "info").lower()

        # Description (English preferred)
        descriptions = cve.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # CWE
        weaknesses = cve.get("weaknesses", [])
        cwe = ""
        if weaknesses:
            cwe_descs = weaknesses[0].get("description", [])
            cwe = next((d["value"] for d in cwe_descs if d.get("lang") == "en"), "")

        # References
        refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

        results.append({
            "cve_id":      cve_id,
            "cvss_v3":     cvss_v3,
            "severity":    severity,
            "cvss_vector": vector,
            "description": description,
            "cwe":         cwe,
            "references":  refs,
        })

    return sorted(results, key=lambda x: x["cvss_v3"], reverse=True)


# ── ExploitDB check ───────────────────────────────────────────────────

def check_exploitdb(cve_id: str) -> Optional[dict]:
    """
    Return the first ExploitDB entry matching this CVE ID, or None.
    Works even if the CSV is not loaded (returns None gracefully).
    """
    if _exploitdb is None:
        return None

    hit = _exploitdb[_exploitdb.apply(
        lambda row: cve_id in str(row.get("codes", "")), axis=1
    )]

    if hit.empty:
        return None

    row = hit.iloc[0]
    return {
        "edb_id":      str(row.get("id", "")),
        "description": str(row.get("description", "")),
        "file":        str(row.get("file", "")),
        "platform":    str(row.get("platform", "")),
        "type":        str(row.get("type", "")),
    }
