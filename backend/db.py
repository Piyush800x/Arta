"""
db.py — SQLite database setup and helpers via aiosqlite.
All tables are created on startup. Functions are thin wrappers
so agents never write raw SQL directly.
"""

import json
import aiosqlite
from config import SQLITE_PATH


# ── Schema ────────────────────────────────────────────────────────────

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
    pdf_path          TEXT
)"""

CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id                   TEXT PRIMARY KEY,
    session_id           TEXT REFERENCES sessions(id),
    cve_id               TEXT,
    cvss_v3              REAL,
    severity             TEXT,
    affected_service     TEXT,
    affected_port        INT,
    detected_version     TEXT,
    exploit_available    BOOLEAN,
    exploit_source       TEXT,
    exploit_succeeded    BOOLEAN,
    evidence_stdout      TEXT,
    owasp_category       TEXT,
    remediation_short    TEXT,
    remediation_package  TEXT,
    remediation_cmd      TEXT
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


# ── Initialisation ────────────────────────────────────────────────────

async def init_db() -> None:
    """Create all tables on first run."""
    async with aiosqlite.connect(SQLITE_PATH) as db:
        await db.execute(CREATE_SESSIONS)
        await db.execute(CREATE_FINDINGS)
        await db.execute(CREATE_LOGS)
        await db.commit()


# ── Sessions ──────────────────────────────────────────────────────────

async def create_session(session: dict) -> None:
    async with aiosqlite.connect(SQLITE_PATH) as db:
        await db.execute(
            """INSERT INTO sessions (id, target_scope, scan_depth, status, created_at)
               VALUES (:id, :target_scope, :scan_depth, :status, :created_at)""",
            session,
        )
        await db.commit()


async def update_session(session_id: str, **fields) -> None:
    """Update any subset of session columns by keyword argument."""
    set_clause = ", ".join(f"{k} = :{k}" for k in fields)
    fields["session_id"] = session_id
    async with aiosqlite.connect(SQLITE_PATH) as db:
        await db.execute(
            f"UPDATE sessions SET {set_clause} WHERE id = :session_id",
            fields,
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


# ── Findings ──────────────────────────────────────────────────────────

async def insert_finding(finding: dict) -> None:
    async with aiosqlite.connect(SQLITE_PATH) as db:
        await db.execute(
            """INSERT INTO findings
               (id, session_id, cve_id, cvss_v3, severity, affected_service,
                affected_port, detected_version, exploit_available, exploit_source,
                exploit_succeeded, evidence_stdout, owasp_category,
                remediation_short, remediation_package, remediation_cmd)
               VALUES
               (:id, :session_id, :cve_id, :cvss_v3, :severity, :affected_service,
                :affected_port, :detected_version, :exploit_available, :exploit_source,
                :exploit_succeeded, :evidence_stdout, :owasp_category,
                :remediation_short, :remediation_package, :remediation_cmd)""",
            finding,
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


# ── Logs ──────────────────────────────────────────────────────────────

async def insert_log(log: dict) -> None:
    """Persist a log event (mirrors what the SSE stream broadcasts)."""
    async with aiosqlite.connect(SQLITE_PATH) as db:
        await db.execute(
            """INSERT INTO logs (id, session_id, ts, agent, level, tool, message, payload)
               VALUES (:id, :session_id, :ts, :agent, :level, :tool, :message, :payload)""",
            {**log, "payload": json.dumps(log.get("payload"))},
        )
        await db.commit()


async def get_recent_logs(session_id: str, limit: int = 50) -> list[dict]:
    """Return the last N log events for SSE reconnect replay."""
    async with aiosqlite.connect(SQLITE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM logs WHERE session_id = ? ORDER BY ts DESC LIMIT ?",
            (session_id, limit),
        ) as cursor:
            rows = [dict(row) async for row in cursor]
            return list(reversed(rows))
