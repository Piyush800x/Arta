"use client";
import styles from "./RiskGauge.module.css";

interface Props {
  score:       number;   // 0–100 from report meta.risk_score
  overallRisk: string;   // CRITICAL | HIGH | MEDIUM | LOW
}

const COLOR: Record<string, string> = {
  CRITICAL: "#ff2d55",
  HIGH:     "#ff9500",
  MEDIUM:   "#ffd60a",
  LOW:      "#30d158",
};

export default function RiskGauge({ score, overallRisk }: Props) {
  const color      = COLOR[overallRisk] ?? "#888";
  const clampedPct = Math.min(100, Math.max(0, score));
  // SVG arc: radius 54, circumference ~339
  const circumference = 2 * Math.PI * 54;
  const dashOffset    = circumference * (1 - clampedPct / 100);

  return (
    <div className={styles.wrap}>
      <svg viewBox="0 0 120 120" className={styles.svg}>
        {/* Track */}
        <circle cx="60" cy="60" r="54" fill="none" stroke="#21262d" strokeWidth="10" />
        {/* Fill */}
        <circle
          cx="60" cy="60" r="54"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          transform="rotate(-90 60 60)"
          style={{ transition: "stroke-dashoffset 1s ease, stroke 0.5s" }}
        />
      </svg>
      <div className={styles.label}>
        <div className={styles.score} style={{ color }}>{score}</div>
        <div className={styles.risk}>{overallRisk}</div>
      </div>
    </div>
  );
}
