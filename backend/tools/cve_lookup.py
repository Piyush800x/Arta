"""
tools/cve_lookup.py — Local CVE and exploit lookup.

Loads the pre-downloaded NVD JSON feed and ExploitDB CSV index once
at startup into memory so agents can query them with zero API calls.
"""

import json
from pathlib import Path
from typing import Optional

import pandas as pd

from config import NVD_JSON_PATH, EXPLOITDB_CSV

# ── In-memory indexes (populated by load_data() at startup) ──────────
_cve_index: dict[str, dict] = {}       # cve_id → CVE record
_exploitdb: Optional[pd.DataFrame] = None


def load_data() -> None:
    """
    Call once at application startup.
    Parses NVD JSON and ExploitDB CSV into memory.
    """
    global _cve_index, _exploitdb

    nvd_path = Path(NVD_JSON_PATH)
    if nvd_path.exists():
        raw = json.loads(nvd_path.read_text(encoding="utf-8"))
        for item in raw.get("CVE_Items", []):
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            _cve_index[cve_id] = item
        print(f"[cve_lookup] Loaded {len(_cve_index)} CVEs from NVD.")
    else:
        print("[cve_lookup] WARNING: NVD JSON not found. Run the night-before setup script.")

    edb_path = Path(EXPLOITDB_CSV)
    if edb_path.exists():
        _exploitdb = pd.read_csv(edb_path, low_memory=False, encoding="utf-8")
        print(f"[cve_lookup] Loaded {len(_exploitdb)} ExploitDB entries.")
    else:
        print("[cve_lookup] WARNING: ExploitDB CSV not found.")


def search_by_product(product: str, version: str, limit: int = 20) -> list[dict]:
    """
    Return up to `limit` CVE records whose CPE string matches
    the given product name and version substring.
    """
    matches = []
    query = f"{product.lower()} {version.lower()}"

    for cve_id, item in _cve_index.items():
        try:
            nodes = item["configurations"]["nodes"]
            for node in nodes:
                for cpe_match in node.get("cpe_match", []):
                    cpe = cpe_match.get("cpe23Uri", "").lower()
                    if product.lower() in cpe and (not version or version.lower() in cpe):
                        cvss = (
                            item.get("impact", {})
                                .get("baseMetricV3", {})
                                .get("cvssV3", {})
                                .get("baseScore", 0.0)
                        )
                        matches.append({
                            "cve_id":  cve_id,
                            "cvss_v3": cvss,
                            "cpe":     cpe,
                        })
                        break
        except (KeyError, TypeError):
            continue

        if len(matches) >= limit:
            break

    return sorted(matches, key=lambda x: x["cvss_v3"], reverse=True)


def check_exploitdb(cve_id: str) -> Optional[dict]:
    """
    Return the first ExploitDB entry matching this CVE ID, or None.
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
        "edb_id":       str(row.get("id", "")),
        "description":  str(row.get("description", "")),
        "file":         str(row.get("file", "")),
        "platform":     str(row.get("platform", "")),
        "type":         str(row.get("type", "")),
    }
