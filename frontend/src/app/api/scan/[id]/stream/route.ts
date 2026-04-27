// app/api/scan/[id]/stream/route.ts
// Proxies the SSE stream from the FastAPI backend to the browser.
// Handles reconnect via Last-Event-ID header forwarding.

import { NextRequest } from "next/server";

const BACKEND = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  const sessionId   = params.id;
  const lastEventId = req.headers.get("Last-Event-ID") ?? "";

  const headers: Record<string, string> = {};
  if (lastEventId) headers["Last-Event-ID"] = lastEventId;

  // Open a persistent SSE connection to the Python backend
  const upstream = await fetch(`${BACKEND}/scan/${sessionId}/stream`, {
    headers,
    // @ts-expect-error — Next.js fetch supports duplex in edge runtime
    duplex: "half",
  });

  if (!upstream.ok || !upstream.body) {
    return new Response("Failed to connect to backend stream", { status: 502 });
  }

  // Pipe the upstream SSE body straight through to the browser
  return new Response(upstream.body, {
    headers: {
      "Content-Type":               "text/event-stream",
      "Cache-Control":              "no-cache",
      "Connection":                 "keep-alive",
      "X-Accel-Buffering":         "no",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
