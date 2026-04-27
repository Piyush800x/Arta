"use client";

import type { Finding } from "@/types";
import styles from "./FindingsTable.module.css";

const SEV_COLOR: Record<string, string> = {
  critical: "var(--sev-critical)",
  high:     "var(--sev-high)",
  medium:   "var(--sev-medium)",
  low:      "var(--sev-low)",
  info:     "var(--sev-info)",
};

interface Props {
  findings: Finding[];
}

export default function FindingsTable({ findings }: Props) {
  if (findings.length === 0) return null;

  return (
    <div className={styles.wrap}>
      <div className={styles.header}>
        <span className={styles.title}>FINDINGS</span>
        <span className={styles.count}>{findings.length} total</span>
      </div>
      <table className={styles.table}>
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>CVSS</th>
            <th>Severity</th>
            <th>Service</th>
            <th>Port</th>
            <th>Version</th>
            <th>Exploit</th>
            <th>Landed</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id}>
              <td className={styles.cveId}>{f.cve_id}</td>
              <td className={styles.cvss}>{f.cvss_v3?.toFixed(1)}</td>
              <td>
                <span
                  className={styles.sevBadge}
                  style={{ background: SEV_COLOR[f.severity] ?? SEV_COLOR.info }}
                >
                  {f.severity}
                </span>
              </td>
              <td>{f.affected_service}</td>
              <td>{f.affected_port}</td>
              <td className={styles.version}>{f.detected_version || "—"}</td>
              <td>
                {f.exploit_available
                  ? <span className={styles.yes}>{f.exploit_source}</span>
                  : <span className={styles.no}>—</span>}
              </td>
              <td>
                {f.exploit_succeeded === true
                  ? <span className={styles.success}>✓ yes</span>
                  : f.exploit_succeeded === false
                    ? <span className={styles.failed}>✗ no</span>
                    : <span className={styles.na}>—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
