"use client";

import { useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
import { getSession, streamUrl } from "@/lib/api";
import type { LogEvent, Finding, Session, SessionStatus } from "@/types";

import AgentStepper   from "@/components/AgentStepper";
import LogFeed        from "@/components/LogFeed";
import FindingsTable  from "@/components/FindingsTable";
import ReportViewer   from "@/components/ReportViewer";
import RiskGauge      from "@/components/RiskGauge";
import styles         from "./page.module.css";

const TERMINAL_STATUSES: SessionStatus[] = ["complete", "error"];
const POLL_INTERVAL_MS = 4000;

export default function ScanPage() {
  const params    = useParams();
  const sessionId = params.id as string;

  const [session,  setSession]  = useState<Session | null>(null);
  const [logs,     setLogs]     = useState<LogEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [pdfUrl,   setPdfUrl]   = useState<string | null>(null);
  const [riskScore, setRiskScore] = useState<number>(0);
  const [overallRisk, setOverallRisk] = useState<string>("");
  const [connErr,  setConnErr]  = useState<string | null>(null);

  const esRef        = useRef<EventSource | null>(null);
  const seenIds      = useRef<Set<string>>(new Set());
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Fetch session + findings (for stepper + table) ──────────────────
  async function refreshSession() {
    try {
      const data = await getSession(sessionId);
      setSession(data.session);
      setFindings(data.findings);
    } catch {
      // silently ignore — the SSE stream is the primary source
    }
  }

  // ── SSE stream ───────────────────────────────────────────────────────
  useEffect(() => {
    refreshSession();

    const url = streamUrl(sessionId);
    const es  = new EventSource(url);
    esRef.current = es;

    es.onmessage = (ev) => {
      try {
        const log: LogEvent = JSON.parse(ev.data);

        // Deduplicate (reconnect may replay past events)
        if (seenIds.current.has(log.id)) return;
        seenIds.current.add(log.id);

        setLogs((prev) => [...prev, log]);

        // PDF_READY event: grab the download URL
        if (log.message === "PDF_READY" && log.payload) {
          setPdfUrl(`/api/report/${sessionId}/pdf`);
          if (log.payload.risk_score) setRiskScore(Number(log.payload.risk_score));
          if (log.payload.overall_risk) setOverallRisk(String(log.payload.overall_risk));
        }

        // Update stepper from log events
        const statusMap: Record<string, SessionStatus> = {
          RECON_STARTED:        "recon",
          VULN_ANALYSIS_STARTED:"vuln_analysis",
          EXPLOIT_ATTEMPT:      "exploiting",
          REPORT_STARTED:       "reporting",
          ALL_AGENTS_COMPLETE:  "complete",
          SESSION_ERROR:        "error",
        };
        for (const [key, status] of Object.entries(statusMap)) {
          if (log.message.startsWith(key)) {
            setSession((prev) => prev ? { ...prev, status } : prev);
          }
        }
      } catch {
        // malformed event — ignore
      }
    };

    es.onerror = () => {
      setConnErr("Stream disconnected — attempting reconnect…");
      // EventSource reconnects automatically; clear error after a moment
      setTimeout(() => setConnErr(null), 3000);
    };

    // Poll for findings & session status periodically
    pollTimerRef.current = setInterval(refreshSession, POLL_INTERVAL_MS);

    return () => {
      es.close();
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  // ── Stop polling when terminal status reached ─────────────────────
  useEffect(() => {
    if (session && TERMINAL_STATUSES.includes(session.status)) {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      esRef.current?.close();
      refreshSession(); // final fetch
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.status]);

  const isDone  = session?.status === "complete";
  const isError = session?.status === "error";

  return (
    <div className={styles.layout}>

      {/* ── Top bar ─────────────────────────────────────────────────── */}
      <header className={styles.topbar}>
        <div className={styles.topbarLeft}>
          <a href="/" className={styles.backLink}>← ARTA</a>
          <span className={styles.sep}>|</span>
          <span className={styles.target}>{session?.target_scope ?? "…"}</span>
        </div>
        <div className={styles.topbarRight}>
          <StatusPill status={session?.status ?? "pending"} />
          {session && (
            <span className={styles.meta}>
              {session.finding_count} finding{session.finding_count !== 1 ? "s" : ""}
              {session.critical_count > 0 && (
                <span className={styles.critical}> · {session.critical_count} critical</span>
              )}
            </span>
          )}
        </div>
      </header>

      {/* ── Agent stepper ───────────────────────────────────────────── */}
      <AgentStepper status={session?.status ?? "pending"} />

      {/* ── Connection error banner ──────────────────────────────────── */}
      {connErr && (
        <div className={styles.connErrBanner}>⚠ &nbsp;{connErr}</div>
      )}

      {/* ── Main content ────────────────────────────────────────────── */}
      <div className={styles.body}>

        {/* Log feed (left / full width when no sidebar) */}
        <section className={styles.logSection}>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionTitle}>AGENT LOG STREAM</span>
            <span className={styles.logCount}>{logs.length} events</span>
          </div>
          <div className={styles.logWrap}>
            <LogFeed logs={logs} autoScroll={!isDone} />
          </div>
        </section>

        {/* Sidebar: findings + report */}
        {(findings.length > 0 || pdfUrl) && (
          <aside className={styles.sidebar}>
            {riskScore > 0 && (
              <div style={{ marginBottom: 24 }}>
                <RiskGauge score={riskScore} overallRisk={overallRisk} />
              </div>
            )}
            {findings.length > 0 && (
              <FindingsTable findings={findings} targetIp={session?.target_scope ?? ""} />
            )}
            {pdfUrl && (
              <div style={{ marginTop: 24 }}>
                <ReportViewer sessionId={sessionId} pdfUrl={pdfUrl} />
              </div>
            )}
          </aside>
        )}
      </div>

      {/* ── Error state ─────────────────────────────────────────────── */}
      {isError && (
        <div className={styles.errorBanner}>
          ✗ &nbsp;Session ended with an error. Check the log above for details.
        </div>
      )}

      {/* ── Complete: no report yet ──────────────────────────────────── */}
      {isDone && !pdfUrl && (
        <div className={styles.waitingPdf}>
          <span className={styles.spinner} /> Generating PDF report…
        </div>
      )}
    </div>
  );
}

// ── Status pill ───────────────────────────────────────────────────────

function StatusPill({ status }: { status: SessionStatus }) {
  const map: Record<SessionStatus, { label: string; cls: string }> = {
    pending:       { label: "PENDING",        cls: styles.pillPending  },
    recon:         { label: "RECON",          cls: styles.pillActive   },
    vuln_analysis: { label: "VULN ANALYSIS",  cls: styles.pillActive   },
    exploiting:    { label: "EXPLOITING",     cls: styles.pillExploit  },
    reporting:     { label: "REPORTING",      cls: styles.pillActive   },
    complete:      { label: "COMPLETE",       cls: styles.pillDone     },
    error:         { label: "ERROR",          cls: styles.pillError    },
  };
  const { label, cls } = map[status] ?? map.pending;
  return <span className={`${styles.pill} ${cls}`}>{label}</span>;
}
