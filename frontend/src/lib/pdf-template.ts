// lib/pdf-template.ts — HTML template rendered by Puppeteer into a PDF

export function buildReportHtml(report: Record<string, unknown>): string {
  const meta     = (report.meta     as Record<string, string>)  ?? {};
  const findings = (report.findings as Record<string, unknown>[]) ?? [];
  const cvssTable= (report.cvss_table as Record<string, unknown>[]) ?? [];
  const runbook  = (report.remediation_runbook as Record<string, unknown>[]) ?? [];
  const timeline = (report.attack_timeline as Record<string, unknown>[]) ?? [];

  const severityColor: Record<string, string> = {
    critical: "#ff2d55",
    high:     "#ff9500",
    medium:   "#ffcc00",
    low:      "#30d158",
    info:     "#636366",
  };

  const findingsHtml = findings.map((f) => `
    <div class="finding">
      <div class="finding-header">
        <span class="cve-id">${f.cve_id}</span>
        <span class="severity-badge" style="background:${severityColor[String(f.severity)] ?? "#888"}">${String(f.severity).toUpperCase()}</span>
        <span class="cvss">CVSS ${f.cvss_v3}</span>
      </div>
      <h3>${f.title}</h3>
      <p><strong>Affected:</strong> ${f.affected}</p>
      <p>${f.description}</p>
      ${f.evidence ? `<pre class="evidence">${f.evidence}</pre>` : ""}
      <p><strong>OWASP:</strong> ${f.owasp ?? "N/A"}</p>
      <div class="remediation">
        <strong>Remediation:</strong>
        <code>${f.remediation}</code>
      </div>
    </div>
  `).join("");

  const cvssRows = cvssTable.map((row) => `
    <tr>
      <td>${row.cve_id}</td>
      <td>${row.cvss_v3}</td>
      <td><span class="severity-badge" style="background:${severityColor[String(row.severity)] ?? "#888"}">${String(row.severity).toUpperCase()}</span></td>
    </tr>
  `).join("");

  const timelineRows = timeline.map((t) => `
    <tr>
      <td>${t.time}</td>
      <td>${t.agent}</td>
      <td>${t.action}</td>
    </tr>
  `).join("");

  const runbookRows = runbook.map((r) => `
    <tr>
      <td>${r.priority}</td>
      <td>${r.cve_id}</td>
      <td>${r.fix}</td>
      <td><code>${r.command}</code></td>
      <td>${r.validation}</td>
    </tr>
  `).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; font-size: 12px; color: #1a1a1a; background: #fff; }

  .cover {
    height: 100vh; display: flex; flex-direction: column;
    justify-content: center; padding: 80px;
    border-left: 8px solid #ff2d55;
  }
  .cover-label { font-size: 10px; letter-spacing: 4px; color: #888; text-transform: uppercase; margin-bottom: 24px; }
  .cover-title { font-size: 48px; font-weight: 900; line-height: 1; color: #000; margin-bottom: 8px; }
  .cover-sub   { font-size: 18px; color: #555; margin-bottom: 48px; }
  .cover-meta  { font-size: 11px; color: #888; line-height: 2; }
  .cover-meta strong { color: #333; }

  .page { padding: 60px; page-break-before: always; }
  h1 { font-size: 22px; font-weight: 900; margin-bottom: 24px; border-bottom: 2px solid #000; padding-bottom: 8px; }
  h2 { font-size: 16px; font-weight: 700; margin: 32px 0 12px; }
  h3 { font-size: 13px; font-weight: 700; margin: 16px 0 8px; }
  p  { line-height: 1.7; margin-bottom: 12px; color: #333; }

  .finding { border: 1px solid #e0e0e0; border-radius: 4px; padding: 20px; margin-bottom: 24px; }
  .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
  .cve-id { font-weight: 900; font-size: 13px; }
  .cvss   { font-size: 11px; color: #888; }
  .severity-badge { font-size: 9px; font-weight: 700; letter-spacing: 1px; color: #fff; padding: 2px 8px; border-radius: 2px; }

  .evidence { background: #1a1a1a; color: #00ff41; padding: 12px; border-radius: 4px; font-size: 10px; margin: 12px 0; white-space: pre-wrap; word-break: break-all; }
  .remediation { background: #f5f5f5; padding: 12px; border-radius: 4px; margin-top: 12px; }
  .remediation code { font-family: 'Courier New', monospace; font-size: 11px; color: #d63031; }

  table { width: 100%; border-collapse: collapse; font-size: 11px; margin-top: 12px; }
  th { background: #1a1a1a; color: #fff; padding: 8px 12px; text-align: left; font-size: 10px; letter-spacing: 1px; }
  td { padding: 8px 12px; border-bottom: 1px solid #eee; vertical-align: top; line-height: 1.5; }
  tr:nth-child(even) td { background: #fafafa; }
  td code { font-family: 'Courier New', monospace; font-size: 10px; color: #d63031; }
</style>
</head>
<body>

<!-- Cover Page -->
<div class="cover">
  <div class="cover-label">Confidential — Penetration Test Report</div>
  <div class="cover-title">ARTA</div>
  <div class="cover-sub">Autonomous Red Team Agent v2.0</div>
  <div class="cover-meta">
    <div><strong>Target</strong> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ${meta.target ?? "N/A"}</div>
    <div><strong>Scan Date</strong> &nbsp; ${meta.scan_date ?? "N/A"}</div>
    <div><strong>Scope</strong> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ${meta.scope ?? "N/A"}</div>
    <div><strong>Classification</strong> ${meta.classification ?? "CONFIDENTIAL"}</div>
  </div>
</div>

<!-- Executive Summary -->
<div class="page">
  <h1>Executive Summary</h1>
  <p>${String(report.executive_summary ?? "").replace(/\n/g, "</p><p>")}</p>

  <h2>Methodology</h2>
  <p>${report.methodology ?? ""}</p>
</div>

<!-- Findings -->
<div class="page">
  <h1>Findings</h1>
  ${findingsHtml || "<p>No findings recorded.</p>"}
</div>

<!-- CVSS Table -->
<div class="page">
  <h1>CVSS Scoring Table</h1>
  <table>
    <thead><tr><th>CVE ID</th><th>CVSS v3</th><th>Severity</th></tr></thead>
    <tbody>${cvssRows || "<tr><td colspan='3'>No data</td></tr>"}</tbody>
  </table>

  <h2>Attack Timeline</h2>
  <table>
    <thead><tr><th>Time</th><th>Agent</th><th>Action</th></tr></thead>
    <tbody>${timelineRows || "<tr><td colspan='3'>No data</td></tr>"}</tbody>
  </table>
</div>

<!-- Remediation Runbook -->
<div class="page">
  <h1>Remediation Runbook</h1>
  <table>
    <thead><tr><th>#</th><th>CVE</th><th>Fix</th><th>Command</th><th>Validation</th></tr></thead>
    <tbody>${runbookRows || "<tr><td colspan='5'>No data</td></tr>"}</tbody>
  </table>
</div>

</body>
</html>`;
}
