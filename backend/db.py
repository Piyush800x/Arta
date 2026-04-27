"""
db.py — SQLite database setup and helpers via aiosqlite.
Updated schema includes the new fields from the enriched vuln agent.
"""

import json
import aiosqlite
from config import SQLITE_PATH


CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    id                TEXT PRIMARY KEY,
    target_scope      TEXT NOT NULL,
    scan_depth        TEXT DEFAULT 'standard',
    status            TEXT DEFAULT 'pending',
    created_at        TEXT,
    completed_at      TEXT,
    finding_count     INT  DEFAULT 0,
    critical_count    INT  DEFAULT 0,
    report_json_path  TEXT,
    pdf_path          TEXT,
    attacker_ip       TEXT,
    attacker_user     TEXT,
    attacker_pass     TEXT
)"""

CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id                   TEXT PRIMARY KEY,
    session_id           TEXT REFERENCES sessions(id),
    cve_id               TEXT,
    cvss_v3              REAL,
    cvss_vector          TEXT,
    severity             TEXT,
    affected_service     TEXT,
    affected_port        INT,
    detected_version     TEXT,
    description          TEXT,
    exploit_available    BOOLEAN,
    exploit_complexity   TEXT,
    attack_vector        TEXT,
    privileges_required  TEXT,
    user_interaction     TEXT,
    exploit_source       TEXT,
    exploit_succeeded    BOOLEAN,
    shell_access         BOOLEAN DEFAULT FALSE,
    evidence_stdout      TEXT,
    owasp_category       TEXT,
    cwe                  TEXT,
    impact               TEXT,
    ranking_reason       TEXT,
    remediation_short    TEXT,
    remediation_package  TEXT,
    remediation_cmd      TEXT,
    "references"         TEXT
)"""

CREATE_LOGS = """
CREATE TABLE IF NOT EXISTS logs (
    id          TEXT PRIMARY KEY,
    session_id  TEXT REFERENCES sessions(id),
    ts          TEXT,
    agent       TEXT,
    level       TEXT,
    tool        TEXT,
    message     TEXT,
    payload     TEXT
)"""


async def init_db() -> None:
    async with aiosqlite.connect(SQLITE_PATH) as db:
        await db.execute(CREATE_SESSIONS)
        await db.execute(CREATE_FINDINGS)
        await db.execute(CREATE_LOGS)
        await db.commit()


async def create_session(session: dict) -> None:
    async with aiosqlite.connect(SQLITE_PATH) as db:
        await db.execute(
            """INSERT INTO sessions (id, target_scope, scan_depth, status, created_at, attacker_ip, attacker_user, attacker_pass)
               VALUES (:id, :target_scope, :scan_depth, :status, :created_at, :attacker_ip, :attacker_user, :attacker_pass)""",
            {
                "attacker_ip": session.get("attacker_ip"),
                "attacker_user": session.get("attacker_user"),
                "attacker_pass": session.get("attacker_pass"),
                **session
            },
        )
        await db.commit()


async def update_session(session_id: str, **fields) -> None:
    set_clause = ", ".join(f"{k} = :{k}" for k in fields)
    fields["session_id"] = session_id
    async with aiosqlite.connect(SQLITE_PATH) as db:
        await db.execute(
            f"UPDATE sessions SET {set_clause} WHERE id = :session_id", fields
        )
        await db.commit()


async def get_session(session_id: str) -> dict | None:
    async with aiosqlite.connect(SQLITE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def insert_finding(finding: dict) -> None:
    # Use INSERT OR REPLACE so exploit agent can update the same row
    async with aiosqlite.connect(SQLITE_PATH) as db:
        await db.execute(
            """INSERT OR REPLACE INTO findings
               (id, session_id, cve_id, cvss_v3, cvss_vector, severity,
                affected_service, affected_port, detected_version, description,
                exploit_available, exploit_complexity, attack_vector,
                privileges_required, user_interaction, exploit_source,
                exploit_succeeded, shell_access, evidence_stdout,
                owasp_category, cwe, impact, ranking_reason,
                remediation_short, remediation_package, remediation_cmd, "references")
               VALUES
               (:id, :session_id, :cve_id, :cvss_v3, :cvss_vector, :severity,
                :affected_service, :affected_port, :detected_version, :description,
                :exploit_available, :exploit_complexity, :attack_vector,
                :privileges_required, :user_interaction, :exploit_source,
                :exploit_succeeded, :shell_access, :evidence_stdout,
                :owasp_category, :cwe, :impact, :ranking_reason,
                :remediation_short, :remediation_package, :remediation_cmd, :references)""",
            {
                "cvss_vector":         finding.get("cvss_vector", ""),
                "description":         finding.get("description", ""),
                "exploit_complexity":  finding.get("exploit_complexity", ""),
                "attack_vector":       finding.get("attack_vector", ""),
                "privileges_required": finding.get("privileges_required", ""),
                "user_interaction":    finding.get("user_interaction", ""),
                "shell_access":        finding.get("shell_access", False),
                "cwe":                 finding.get("cwe", ""),
                "impact":              finding.get("impact", ""),
                "ranking_reason":      finding.get("ranking_reason", ""),
                "references":          finding.get("references", "[]"),
                **{k: finding.get(k) for k in (
                    "id", "session_id", "cve_id", "cvss_v3", "severity",
                    "affected_service", "affected_port", "detected_version",
                    "exploit_available", "exploit_source", "exploit_succeeded",
                    "evidence_stdout", "owasp_category",
                    "remediation_short", "remediation_package", "remediation_cmd",
                )},
            },
        )
        await db.commit()


async def get_findings(session_id: str) -> list[dict]:
    async with aiosqlite.connect(SQLITE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY cvss_v3 DESC",
            (session_id,),
        ) as cursor:
            return [dict(row) async for row in cursor]


async def insert_log(log: dict) -> None:
    async with aiosqlite.connect(SQLITE_PATH) as db:
        await db.execute(
            """INSERT OR IGNORE INTO logs
               (id, session_id, ts, agent, level, tool, message, payload)
               VALUES (:id, :session_id, :ts, :agent, :level, :tool, :message, :payload)""",
            {**log, "payload": json.dumps(log.get("payload"))},
        )
        await db.commit()


async def get_recent_logs(session_id: str, limit: int = 200) -> list[dict]:
    async with aiosqlite.connect(SQLITE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM logs WHERE session_id = ? ORDER BY ts ASC LIMIT ?",
            (session_id, limit),
        ) as cursor:
            return [dict(row) async for row in cursor]
