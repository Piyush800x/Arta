import { useState } from "react";
import type { Finding } from "@/types";
import styles from "./FindingsTable.module.css";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const SEV_COLOR: Record<string, string> = {
  critical: "var(--sev-critical)",
  high:     "var(--sev-high)",
  medium:   "var(--sev-medium)",
  low:      "var(--sev-low)",
  info:     "var(--sev-info)",
};

interface Props {
  findings: Finding[];
  targetIp: string;
}

export default function FindingsTable({ findings, targetIp }: Props) {
  const [verifying, setVerifying] = useState<string | null>(null);
  const [rescanResults, setRescanResults] = useState<Record<string, string>>({});

  async function verifFix(f: Finding) {
    setVerifying(f.id);
    try {
      const res = await fetch(`${API}/rescan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_id: f.id,
          target_ip:  targetIp,
          port:       f.affected_port,
          service:    f.affected_service,
        }),
      });
      const data = await res.json();
      setRescanResults(prev => ({ ...prev, [f.id]: data.status }));
    } catch (err) {
      console.error("Rescan failed:", err);
    } finally {
      setVerifying(null);
    }
  }

  if (findings.length === 0) return null;

  return (
    <div className={styles.wrap}>
      <div className={styles.header}>
        <span className={styles.title}>FINDINGS</span>
        <span className={styles.count}>{findings.length} total</span>
      </div>
      <div className={styles.tableWrap}>
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
              <th>Validation</th>
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
                <td className={styles.verifyCol}>
                  {rescanResults[f.id] === "verified_fixed" && (
                    <span className={styles.fixed}>✓ Fixed</span>
                  )}
                  {rescanResults[f.id] === "still_vulnerable" && (
                    <span className={styles.vuln}>✗ Still open</span>
                  )}
                  {!rescanResults[f.id] && (
                    <button
                      onClick={() => verifFix(f)}
                      disabled={verifying === f.id}
                      className={styles.verifyBtn}
                    >
                      {verifying === f.id ? "Scanning…" : "Verify Fix"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
