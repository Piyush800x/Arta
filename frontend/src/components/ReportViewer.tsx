"use client";

import styles from "./ReportViewer.module.css";

interface Props {
  sessionId: string;
  pdfUrl:    string;          // e.g. /api/report/{id}/pdf
}

export default function ReportViewer({ sessionId, pdfUrl }: Props) {
  return (
    <div className={styles.wrap}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.titleRow}>
          <span className={styles.icon}>◈</span>
          <span className={styles.title}>PENTEST REPORT READY</span>
        </div>
        <a
          href={pdfUrl}
          download={`arta-report-${sessionId}.pdf`}
          className={styles.downloadBtn}
        >
          ↓ Download PDF
        </a>
      </div>

      {/* Inline preview */}
      <iframe
        src={pdfUrl}
        className={styles.iframe}
        title="Pentest Report Preview"
      />
    </div>
  );
}
