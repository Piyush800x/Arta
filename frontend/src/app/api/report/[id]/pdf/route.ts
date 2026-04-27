// app/api/report/[id]/pdf/route.ts
// Fetches the report JSON from the backend, renders it as HTML,
// and uses Puppeteer (headless Chrome) to produce a PDF binary.

import { NextRequest, NextResponse } from "next/server";
import puppeteer from "puppeteer";
import { buildReportHtml } from "@/lib/pdf-template";

const BACKEND = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  const sessionId = params.id;

  // ── 1. Fetch report JSON from the Python backend ───────────────────
  let report: Record<string, unknown>;
  try {
    const res = await fetch(`${BACKEND}/report/${sessionId}`);
    if (!res.ok) {
      return NextResponse.json(
        { detail: "Report not yet generated" },
        { status: 404 }
      );
    }
    report = await res.json();
  } catch {
    return NextResponse.json(
      { detail: "Failed to fetch report from backend" },
      { status: 502 }
    );
  }

  // ── 2. Build HTML from the report data ────────────────────────────
  const html = buildReportHtml(report);

  // ── 3. Puppeteer → PDF ────────────────────────────────────────────
  let pdfBuffer: Buffer;
  try {
    const browser = await puppeteer.launch({
      headless: true,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
      ],
    });

    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle0" });

    pdfBuffer = Buffer.from(
      await page.pdf({
        format:          "A4",
        printBackground: true,
        margin: {
          top:    "20mm",
          right:  "18mm",
          bottom: "20mm",
          left:   "18mm",
        },
      })
    );

    await browser.close();
  } catch (err) {
    console.error("[pdf-route] Puppeteer error:", err);
    return NextResponse.json(
      { detail: "PDF generation failed. Is Puppeteer installed?" },
      { status: 500 }
    );
  }

  // ── 4. Return PDF binary ──────────────────────────────────────────
  return new Response(pdfBuffer, {
    headers: {
      "Content-Type":        "application/pdf",
      "Content-Disposition": `inline; filename="arta-report-${sessionId}.pdf"`,
      "Cache-Control":       "no-store",
    },
  });
}
