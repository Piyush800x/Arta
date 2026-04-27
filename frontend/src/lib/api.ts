// lib/api.ts — typed wrappers for every backend endpoint

import type { ScanDepth, ScanResponse, Session, Finding } from "@/types";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ── Start a scan ──────────────────────────────────────────────────────

export async function startScan(
  targetIp: string,
  scanDepth: ScanDepth,
  authorised: boolean
): Promise<ScanResponse> {
  const res = await fetch(`${BASE}/scan`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ target_ip: targetIp, scan_depth: scanDepth, authorised }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail ?? `Failed to start scan (${res.status})`);
  }
  return res.json();
}

// ── Fetch session status + findings ──────────────────────────────────

export async function getSession(
  sessionId: string
): Promise<{ session: Session; findings: Finding[] }> {
  const res = await fetch(`${BASE}/scan/${sessionId}`);
  if (!res.ok) throw new Error(`Session not found (${res.status})`);
  return res.json();
}

// ── Fetch full report JSON ────────────────────────────────────────────

export async function getReport(sessionId: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${BASE}/report/${sessionId}`);
  if (!res.ok) throw new Error(`Report not ready (${res.status})`);
  return res.json();
}

// ── SSE stream URL (used directly by EventSource) ────────────────────

export function streamUrl(sessionId: string): string {
  return `${BASE}/scan/${sessionId}/stream`;
}
