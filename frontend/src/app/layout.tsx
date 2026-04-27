import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ARTA — Autonomous Red Team Agent",
  description: "Zero-budget autonomous penetration testing powered by Gemini",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
