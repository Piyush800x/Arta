"""
events.py — Log event factory and queue broadcaster.

Every agent calls emit() to push a structured log event to:
  1. The asyncio.Queue  → forwarded to the SSE stream → browser
  2. SQLite logs table  → persisted for reconnect replay

LogEvent shape matches the TypeScript type in the PRD exactly.
"""

import uuid
from datetime import datetime, timezone
from typing import Any
import asyncio

import db

# The live queue — wired up in main.py and passed to agents.
# Agents call emit(); main.py's SSE handler reads from this queue.
_queue: asyncio.Queue | None = None


def set_queue(q: asyncio.Queue) -> None:
    global _queue
    _queue = q


async def emit(
    session_id: str,
    agent: str,
    level: str,
    message: str,
    tool: str | None = None,
    payload: Any = None,
    duration_ms: int | None = None,
) -> None:
    """Build a LogEvent, push to queue, and persist to SQLite."""
    event = {
        "id":          str(uuid.uuid4()),
        "session_id":  session_id,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "agent":       agent,
        "level":       level,
        "tool":        tool,
        "message":     message,
        "payload":     payload,
        "duration_ms": duration_ms,
    }

    # Push to live SSE stream
    if _queue is not None:
        await _queue.put(event)

    # Persist for reconnect replay
    await db.insert_log(event)
