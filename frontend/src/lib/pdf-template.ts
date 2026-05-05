// lib/pdf-template.ts — HTML template rendered by Puppeteer into a PDF
import { buildTopologySvg } from "./topology-svg";

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

  // ── Helpers ─────────────────────────────────────────────────────────
  function safeStr(v: unknown, fallback = "—"): string {
    if (v === null || v === undefined) return fallback;
    if (typeof v === "object")         return fallback;
    const s = String(v).trim();
    return s === "" || s === "null" || s === "undefined" ? fallback : s;
  }

  /**
   * Lightweight markdown → HTML converter.
   * Handles: headers, bold, italic, inline code, code blocks,
   * unordered/ordered lists, and paragraph breaks.
   */
  function mdToHtml(raw: unknown): string {
    if (raw === null || raw === undefined) return "";
    let text = String(raw);

    // Fenced code blocks  ```lang ... ```
    text = text.replace(/```[\w]*\n([\s\S]*?)```/g, '<pre class="evidence">$1</pre>');

    // Inline code  `code`
    text = text.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Headers  ## → <strong> (we don't want giant headings inside a paragraph)
    text = text.replace(/^#{1,4}\s+(.+)$/gm, '<strong>$1</strong>');

    // Bold  **text** or __text__
    text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    text = text.replace(/__(.+?)__/g, '<strong>$1</strong>');

    // Italic  *text* or _text_  (but not inside words like some_var)
    text = text.replace(/(?<![\w])\*([^*]+?)\*(?![\w])/g, '<em>$1</em>');
    text = text.replace(/(?<![\w])_([^_]+?)_(?![\w])/g, '<em>$1</em>');

    // Unordered list items  - item  or  * item
    text = text.replace(/^[\-\*]\s+(.+)$/gm, '<li>$1</li>');
    // Wrap consecutive <li> in <ul>
    text = text.replace(/((?:<li>.*<\/li>\n?)+)/g, '<ul>$1</ul>');

    // Ordered list items  1. item
    text = text.replace(/^\d+\.\s+(.+)$/gm, '<li>$1</li>');
    text = text.replace(/((?:<li>.*<\/li>\n?)+)/g, (match) => {
      // Only wrap in <ol> if not already wrapped
      if (match.startsWith('<ul>') || match.startsWith('<ol>')) return match;
      return `<ol>${match}</ol>`;
    });

    // Paragraph breaks (double newline → </p><p>)
    text = text.replace(/\n\n+/g, '</p><p>');
    // Single newlines → <br>
    text = text.replace(/\n/g, '<br>');

    return text;
  }

  function sevBadge(sev: string): string {
    const color = severityColor[sev.toLowerCase()] ?? "#888";
    return `<span class="severity-badge" style="background:${color}">${sev.toUpperCase()}</span>`;
  }

  function remediationBlock(f: Record<string, unknown>): string {
    const rem = (typeof f.remediation === "object" && f.remediation !== null)
      ? (f.remediation as Record<string, unknown>)
      : {};

    const short   = safeStr(rem.short   ?? f.remediation_short);
    const detail  = safeStr(rem.detail,  "");
    const command = safeStr(rem.command  ?? f.remediation_cmd,     "");
    const pkg     = safeStr(rem.package  ?? f.remediation_package, "");
    const valid   = safeStr(rem.validation, "");

    return `
      <div class="remediation">
        <div class="rem-title">Remediation</div>
        <div class="rem-short">${short}</div>
        ${detail  ? `<p style="font-size:11px;color:#555;margin:6px 0">${detail}</p>` : ""}
        ${pkg     ? `<div class="exrow"><strong>Package:</strong> ${pkg}</div>` : ""}
        ${command ? `<pre class="cmd">${command}</pre>` : ""}
        ${valid   ? `<div class="exrow"><strong>Validation:</strong> ${valid}</div>` : ""}
      </div>`;
  }

  // ── Renderers ───────────────────────────────────────────────────────

  const findingsHtml = findings.map((f) => {
    const owasp = safeStr(
      f.owasp_category ?? 
      (f.exploit_result as Record<string,unknown> | null)?.owasp_category ??
      f.owasp
    );
    
    return `
      <div class="finding">
        <div class="finding-header">
          <span class="cve-id">${f.cve_id}</span>
          ${sevBadge(String(f.severity))}
          <span class="cvss">CVSS ${f.cvss_v3}</span>
        </div>
        <h3>${f.title}</h3>
        <p><strong>Affected:</strong> ${f.affected_component ?? f.affected}</p>
        <p>${mdToHtml(f.description)}</p>
        ${f.technical_detail ? `<p>${mdToHtml(f.technical_detail)}</p>` : ""}
        ${f.evidence_stdout || f.evidence ? `<pre class="evidence">${f.evidence_stdout || f.evidence}</pre>` : ""}
        <p><strong>OWASP:</strong> ${owasp}</p>
        ${remediationBlock(f)}
      </div>`;
  }).join("");

  const cvssRows = cvssTable.map((row) => `
    <tr>
      <td>${row.cve_id}</td>
      <td>${row.cvss_v3}</td>
      <td>${sevBadge(String(row.severity))}</td>
    </tr>
  `).join("");

  const timelineRows = timeline.map((t) => {
    const time   = safeStr(t.time_offset ?? t.time ?? t.timestamp);
    const agent  = safeStr(t.agent ?? t.phase ?? t.who);
    const action = safeStr(t.action ?? t.description);
    const outcome= safeStr(t.outcome, "");

    return `
      <tr>
        <td>${time}</td>
        <td>${agent}</td>
        <td>${action}</td>
        <td>${outcome}</td>
      </tr>`;
  }).join("");

  const runbookRows = runbook.map((r) => {
    const fix     = safeStr(r.fix_summary ?? r.fix ?? r.short ?? r.remediation_short);
    const command = safeStr(r.command ?? r.remediation_cmd, "");
    const valid   = safeStr(r.validation, "");
    const effort  = safeStr(r.estimated_effort, "");

    const steps = Array.isArray(r.steps)
      ? `<ol style="margin:4px 0 0 14px;font-size:10px">${(r.steps as unknown[]).map(s => `<li>${s}</li>`).join("")}</ol>`
      : "";

    return `
      <tr>
        <td style="font-weight:700">${safeStr(r.priority)}</td>
        <td>${sevBadge(String(r.severity ?? "info"))}</td>
        <td style="font-weight:700">${safeStr(r.cve_id)}</td>
        <td>${fix}${steps}</td>
        <td>${command ? `<code>${command}</code>` : "—"}</td>
        <td>${valid}</td>
        <td>${effort}</td>
      </tr>`;
  }).join("");

  // Feature 5 — Narrative
  const narrative = String(report.attack_narrative ?? "");

  // Bug 5 Fix: open_ports extraction
  const recon      = (report.recon as Record<string, unknown>) ?? {};
  const rawPorts   = (recon.open_ports ?? report.open_ports) as Record<string, unknown>[] ?? [];
  const openPorts  = rawPorts
    .filter(p => p && p.port)
    .map(p => ({
      port:     Number(p.port),
      service:  String(p.service  ?? "unknown"),
      severity: String(
        findings.find(f => Number(f.affected_port) === Number(p.port))?.severity ?? "info"
      ),
    }));
  const topologySvg = buildTopologySvg(String(meta.target ?? "N/A"), openPorts);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; font-size: 12px; color: #1a1a1a; background: #fff; }

  .cover {
    min-height: 100vh; display: flex; flex-direction: column;
    justify-content: center; padding: 96px 80px;
    border-left: 8px solid #ff2d55;
  }
  .cover-label { font-size: 10px; letter-spacing: 4px; color: #888; text-transform: uppercase; margin-bottom: 24px; }
  .cover-title { font-size: 48px; font-weight: 900; line-height: 1; color: #000; margin-bottom: 8px; }
  .cover-sub   { font-size: 18px; color: #555; margin-bottom: 48px; }
  .cover-meta  { font-size: 11px; color: #888; line-height: 2; }
  .cover-meta strong { color: #333; }

  .page { padding: 64px 72px; page-break-before: always; }
  h1 { font-size: 22px; font-weight: 900; margin-bottom: 24px; border-bottom: 2px solid #000; padding-bottom: 8px; }
  h2 { font-size: 16px; font-weight: 700; margin: 32px 0 12px; }
  h3 { font-size: 13px; font-weight: 700; margin: 16px 0 8px; }
  p  { line-height: 1.7; margin-bottom: 12px; color: #333; }

  .finding { border: 1px solid #e0e0e0; border-radius: 4px; padding: 20px; margin-bottom: 24px; }
  .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
  .cve-id { font-weight: 900; font-size: 13px; }
  .cvss   { font-size: 11px; color: #888; }
  .severity-badge { font-size: 9px; font-weight: 700; letter-spacing: 1px; color: #fff; padding: 2px 8px; border-radius: 2px; text-transform: uppercase; }

  .evidence { background: #1a1a1a; color: #00ff41; padding: 12px; border-radius: 4px; font-size: 10px; margin: 12px 0; white-space: pre-wrap; word-break: break-all; }
  
  .remediation { background: #f5f5f5; padding: 16px; border-radius: 4px; margin-top: 12px; border-left: 3px solid #ccc; }
  .rem-title { font-weight: 900; font-size: 10px; text-transform: uppercase; color: #888; margin-bottom: 4px; }
  .rem-short { font-weight: 700; color: #000; font-size: 12px; }
  .exrow { font-size: 10px; margin-top: 4px; color: #666; }
  pre.cmd { background: #eee; padding: 8px; border-radius: 3px; font-size: 10px; color: #d63031; margin-top: 8px; overflow-x: auto; }

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
  <p>${mdToHtml(report.executive_summary)}</p>

  <h2>Network Topology</h2>
  ${topologySvg}

  ${narrative ? `
  <h2>Attack Narrative</h2>
  <div style="border-left:3px solid #ff2d55;padding:0 0 0 16px;margin:12px 0">
    <p style="font-style:italic;color:#555">${mdToHtml(narrative)}</p>
  </div>` : ""}

  <h2>Methodology</h2>
  <p>
    ${typeof report.methodology === 'object' && report.methodology !== null ?
      `<strong>Approach:</strong> ${(report.methodology as any).approach || ''}<br/><br/>
      <strong>Tools:</strong> ${((report.methodology as any).tools_used || []).join(', ')}<br/><br/>
      <strong>Phases:</strong><br/>
      ${((report.methodology as any).phases || []).map((p: any) => `<em>${p.phase}:</em> ${p.description}`).join('<br/>')}`
      : report.methodology ?? ""
    }
  </p>
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
    <thead><tr><th>Time</th><th>Agent</th><th>Action</th><th>Outcome</th></tr></thead>
    <tbody>${timelineRows || "<tr><td colspan='4'>No data</td></tr>"}</tbody>
  </table>
</div>

<!-- Remediation Runbook -->
<div class="page">
  <h1>Remediation Runbook</h1>
  <table>
    <thead><tr><th>#</th><th>Sev</th><th>CVE</th><th>Fix</th><th>Command</th><th>Validation</th><th>Effort</th></tr></thead>
    <tbody>${runbookRows || "<tr><td colspan='7'>No data</td></tr>"}</tbody>
  </table>
</div>

</body>
</html>`;
}
