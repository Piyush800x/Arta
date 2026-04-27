// types/index.ts — shared types used across all pages and components

export type AgentName = "orchestrator" | "recon" | "vuln" | "exploit" | "report";
export type LogLevel  = "info" | "warning" | "error" | "success" | "gemini" | "tool";
export type ScanDepth = "standard" | "full";
export type SessionStatus =
  | "pending"
  | "recon"
  | "vuln_analysis"
  | "exploiting"
  | "reporting"
  | "complete"
  | "error";

export interface LogEvent {
  id:          string;
  session_id:  string;
  timestamp:   string;   // ISO 8601
  agent:       AgentName;
  level:       LogLevel;
  tool:        string | null;
  message:     string;
  payload:     Record<string, unknown> | null;
  duration_ms: number | null;
}

export interface Finding {
  id:                   string;
  session_id:           string;
  cve_id:               string;
  cvss_v3:              number;
  severity:             "critical" | "high" | "medium" | "low" | "info";
  affected_service:     string;
  affected_port:        number;
  detected_version:     string;
  exploit_available:    boolean;
  exploit_source:       string;
  exploit_succeeded:    boolean;
  evidence_stdout:      string | null;
  owasp_category:       string | null;
  remediation_short:    string | null;
  remediation_package:  string | null;
  remediation_cmd:      string | null;
}

export interface Session {
  id:               string;
  target_scope:     string;
  scan_depth:       ScanDepth;
  status:           SessionStatus;
  created_at:       string;
  completed_at:     string | null;
  finding_count:    number;
  critical_count:   number;
  report_json_path: string | null;
  pdf_path:         string | null;
}

export interface ScanResponse {
  session_id: string;
  status:     string;
  stream_url: string;
}
