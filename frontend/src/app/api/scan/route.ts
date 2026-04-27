// app/api/scan/route.ts
// Proxies the scan request from the browser to the FastAPI backend.
// The browser never needs to know the backend URL.

import { NextRequest, NextResponse } from "next/server";

const BACKEND = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();

    const res = await fetch(`${BACKEND}/scan`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    });

    const data = await res.json();

    if (!res.ok) {
      return NextResponse.json(data, { status: res.status });
    }

    return NextResponse.json(data);
  } catch {
    return NextResponse.json(
      { detail: "Failed to reach ARTA backend. Is it running on port 8000?" },
      { status: 502 }
    );
  }
}
