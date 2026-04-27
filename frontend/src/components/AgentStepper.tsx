"use client";

import type { SessionStatus } from "@/types";
import styles from "./AgentStepper.module.css";

const STEPS: { key: SessionStatus; label: string; short: string }[] = [
  { key: "recon",        label: "Reconnaissance", short: "Recon"  },
  { key: "vuln_analysis",label: "Vuln Analysis",  short: "Vuln"   },
  { key: "exploiting",   label: "Exploit",        short: "Exploit"},
  { key: "reporting",    label: "Report Gen",     short: "Report" },
];

// Ordered list of statuses for progress comparison
const STATUS_ORDER: SessionStatus[] = [
  "pending", "recon", "vuln_analysis", "exploiting", "reporting", "complete", "error",
];

type StepState = "pending" | "active" | "done" | "error";

function stepState(stepKey: SessionStatus, sessionStatus: SessionStatus): StepState {
  if (sessionStatus === "error") return "error";
  const stepIdx   = STATUS_ORDER.indexOf(stepKey);
  const curIdx    = STATUS_ORDER.indexOf(sessionStatus);
  if (curIdx > stepIdx)  return "done";
  if (curIdx === stepIdx) return "active";
  return "pending";
}

interface Props {
  status: SessionStatus;
}

export default function AgentStepper({ status }: Props) {
  return (
    <div className={styles.stepper}>
      {STEPS.map((step, i) => {
        const state = stepState(step.key, status);
        return (
          <div key={step.key} className={styles.stepRow}>
            <div className={`${styles.step} ${styles[state]}`}>
              <div className={styles.indicator}>
                {state === "done"   && <span className={styles.check}>✓</span>}
                {state === "active" && <span className={styles.pulse} />}
                {state === "pending"&& <span className={styles.num}>{i + 1}</span>}
                {state === "error"  && <span className={styles.errX}>✗</span>}
              </div>
              <div className={styles.stepLabel}>
                <span className={styles.stepName}>{step.label}</span>
                <span className={styles.stepState}>{state}</span>
              </div>
            </div>
            {i < STEPS.length - 1 && (
              <div className={`${styles.connector} ${state === "done" ? styles.connectorDone : ""}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}
