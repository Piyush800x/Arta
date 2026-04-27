"use client";

import { useEffect, useRef } from "react";
import type { LogEvent, AgentName, LogLevel } from "@/types";
import styles from "./LogFeed.module.css";

// ── Colour maps ───────────────────────────────────────────────────────

const LEVEL_CLASS: Record<LogLevel, string> = {
  info:    styles.levelInfo,
  gemini:  styles.levelGemini,
  success: styles.levelSuccess,
  warning: styles.levelWarning,
  error:   styles.levelError,
  tool:    styles.levelTool,
};

const AGENT_CLASS: Record<AgentName, string> = {
  orchestrator: styles.agentOrchestrator,
  recon:        styles.agentRecon,
  vuln:         styles.agentVuln,
  exploit:      styles.agentExploit,
  report:       styles.agentReport,
};

const LEVEL_ICON: Record<LogLevel, string> = {
  info:    "·",
  gemini:  "◈",
  success: "✓",
  warning: "⚠",
  error:   "✗",
  tool:    "▸",
};

// ── Helpers ───────────────────────────────────────────────────────────

function formatTime(iso: string): string {
  if (!iso) return "--:--:--";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "--:--:--";
    return d.toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return "--:--:--";
  }
}

// ── Component ─────────────────────────────────────────────────────────

interface Props {
  logs: LogEvent[];
  autoScroll?: boolean;
}

export default function LogFeed({ logs, autoScroll = true }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, autoScroll]);

  if (logs.length === 0) {
    return (
      <div className={styles.empty}>
        <span className={styles.cursor} />
        Waiting for agent output…
      </div>
    );
  }

  return (
    <div className={styles.feed}>
      {logs.map((log) => (
        <div
          key={log.id}
          className={`${styles.row} ${LEVEL_CLASS[log.level] ?? ""}`}
          style={{ animationDelay: "0ms" }}
        >
          {/* Time */}
          <span className={styles.time}>{formatTime(log.ts)}</span>

          {/* Agent badge */}
          <span className={`${styles.agent} ${AGENT_CLASS[log.agent] ?? ""}`}>
            {log.agent.toUpperCase().padEnd(13)}
          </span>

          {/* Level icon */}
          <span className={styles.icon}>{LEVEL_ICON[log.level] ?? "·"}</span>

          {/* Message */}
          <span className={styles.message}>{log.message}</span>

          {/* Duration */}
          {log.duration_ms != null && (
            <span className={styles.duration}>{log.duration_ms}ms</span>
          )}

          {/* Tool tag */}
          {log.tool && (
            <span className={styles.tool}>[{log.tool}]</span>
          )}

          {/* Feature 4 — Live Exploit Terminal */}
          {log.payload?.evidence_stdout && (
            <div className={styles.terminalBlock}>
              <pre className={styles.terminalOut}>
                {String(log.payload.evidence_stdout).slice(0, 1000)}
              </pre>
            </div>
          )}
        </div>
      ))}

      {/* Blinking cursor at the bottom */}
      <div className={styles.cursorRow}>
        <span className={styles.cursor} />
      </div>

      <div ref={bottomRef} />
    </div>
  );
}
