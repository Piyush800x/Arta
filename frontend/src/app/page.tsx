"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { startScan } from "@/lib/api";
import type { ScanDepth } from "@/types";
import styles from "./page.module.css";

export default function HomePage() {
  const router = useRouter();

  const [targetIp, setTargetIp]     = useState("");
  const [scanDepth, setScanDepth]   = useState<ScanDepth>("standard");
  const [authorised, setAuthorised] = useState(false);
  
  const [useRemote, setUseRemote]   = useState(false);
  const [attackerIp, setAttackerIp] = useState("");
  const [attackerUser, setAttackerUser] = useState("");
  const [attackerPass, setAttackerPass] = useState("");

  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState<string | null>(null);

  async function handleSubmit() {
    if (!targetIp.trim())  return setError("Target IP is required.");
    if (!authorised)       return setError("You must confirm authorisation before scanning.");

    setError(null);
    setLoading(true);
    try {
      const res = await startScan(
        targetIp.trim(), 
        scanDepth, 
        authorised,
        useRemote ? attackerIp.trim() : undefined,
        useRemote ? attackerUser.trim() : undefined,
        useRemote ? attackerPass : undefined
      );
      router.push(`/scan/${res.session_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start scan.");
      setLoading(false);
    }
  }

  return (
    <main className={styles.main}>
      {/* Header */}
      <header className={styles.header}>
        <div className={styles.logo}>
          <span className={styles.logoBracket}>[</span>
          ARTA
          <span className={styles.logoBracket}>]</span>
        </div>
        <div className={styles.tagline}>
          Autonomous Red Team Agent &nbsp;·&nbsp; v2.0 &nbsp;·&nbsp; Gemini-powered
        </div>
      </header>

      {/* Hero */}
      <section className={styles.hero}>
        <div className={styles.heroGlow} />
        <h1 className={styles.heroTitle}>
          Penetration testing,<br />
          <span className={styles.heroAccent}>fully autonomous.</span>
        </h1>
        <p className={styles.heroSub}>
          Recon → Vulnerability analysis → Exploit → PDF report.
          <br />Zero cloud spend. Powered by Gemini 2.0 Flash.
        </p>
      </section>

      {/* Scan form */}
      <section className={styles.formCard}>
        <div className={styles.formCardHeader}>
          <span className={styles.dot} style={{ background: "#ff5f57" }} />
          <span className={styles.dot} style={{ background: "#febc2e" }} />
          <span className={styles.dot} style={{ background: "#28c840" }} />
          <span className={styles.formCardTitle}>new_scan.sh</span>
        </div>

        <div className={styles.formBody}>
          {/* Target IP */}
          <div className={styles.field}>
            <label className={styles.label}>
              <span className={styles.prompt}>$</span> TARGET_IP
            </label>
            <input
              className={styles.input}
              type="text"
              placeholder="192.168.56.101"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              disabled={loading}
              spellCheck={false}
              autoFocus
            />
          </div>

          {/* Scan depth */}
          <div className={styles.field}>
            <label className={styles.label}>
              <span className={styles.prompt}>$</span> SCAN_DEPTH
            </label>
            <div className={styles.radioGroup}>
              {(["standard", "full"] as ScanDepth[]).map((d) => (
                <button
                  key={d}
                  type="button"
                  className={`${styles.radioBtn} ${scanDepth === d ? styles.radioBtnActive : ""}`}
                  onClick={() => setScanDepth(d)}
                  disabled={loading}
                >
                  {d === "standard" ? "standard  (-sV -sC --open)" : "full  (-p- all ports)"}
                </button>
              ))}
            </div>
          </div>

          {/* Remote Attacker VM */}
          <div className={styles.field} style={{ marginTop: "16px", borderTop: "1px solid #222", paddingTop: "16px" }}>
            <label className={styles.authCheck} style={{ marginBottom: "12px" }}>
              <input
                type="checkbox"
                checked={useRemote}
                onChange={(e) => setUseRemote(e.target.checked)}
                disabled={loading}
                className={styles.checkbox}
              />
              <span className={styles.authText} style={{ color: "#00ff41", fontWeight: "bold" }}>
                Enable Remote Attacker Mode (SSH into Kali VM for Nmap/MSF)
              </span>
            </label>

            {useRemote && (
              <div style={{ display: "flex", gap: "12px", marginTop: "12px" }}>
                <input
                  className={styles.input}
                  style={{ flex: 1 }}
                  type="text"
                  placeholder="Attacker IP"
                  value={attackerIp}
                  onChange={(e) => setAttackerIp(e.target.value)}
                  disabled={loading}
                  spellCheck={false}
                />
                <input
                  className={styles.input}
                  style={{ flex: 1 }}
                  type="text"
                  placeholder="Username"
                  value={attackerUser}
                  onChange={(e) => setAttackerUser(e.target.value)}
                  disabled={loading}
                  spellCheck={false}
                />
                <input
                  className={styles.input}
                  style={{ flex: 1 }}
                  type="password"
                  placeholder="Password"
                  value={attackerPass}
                  onChange={(e) => setAttackerPass(e.target.value)}
                  disabled={loading}
                />
              </div>
            )}
          </div>

          {/* Authorisation */}
          <label className={styles.authCheck}>
            <input
              type="checkbox"
              checked={authorised}
              onChange={(e) => setAuthorised(e.target.checked)}
              disabled={loading}
              className={styles.checkbox}
            />
            <span className={styles.authText}>
              I confirm I am the owner of, or have explicit written authorisation to test,
              the system at the IP address above.
            </span>
          </label>

          {/* Error */}
          {error && <div className={styles.error}>✗ &nbsp;{error}</div>}

          {/* Submit */}
          <button
            className={styles.submitBtn}
            onClick={handleSubmit}
            disabled={loading || !targetIp || !authorised}
          >
            {loading ? (
              <>
                <span className={styles.spinner} />
                Initialising session…
              </>
            ) : (
              <>
                <span className={styles.submitArrow}>▶</span>
                Launch ARTA
              </>
            )}
          </button>
        </div>
      </section>

      {/* Pipeline preview */}
      <section className={styles.pipeline}>
        {["Recon", "Vuln Analysis", "Exploit", "Report"].map((step, i) => (
          <div key={step} className={styles.pipelineStep}>
            <div className={styles.pipelineNum}>0{i + 1}</div>
            <div className={styles.pipelineName}>{step}</div>
            {i < 3 && <div className={styles.pipelineArrow}>→</div>}
          </div>
        ))}
      </section>

      <footer className={styles.footer}>
        Bot to Agent Hackathon &nbsp;·&nbsp; IEM Kolkata &nbsp;·&nbsp; 27 April 2026
        &nbsp;·&nbsp; Total infrastructure cost: ₹0
      </footer>
    </main>
  );
}
