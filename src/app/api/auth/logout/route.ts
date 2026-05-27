import { NextRequest, NextResponse } from "next/server";
import { connectToDatabase } from "@/lib/db";
import { clearSessionCookie, verifySessionCookie } from "@/lib/session-cookie";
import { BobSession } from "@/models/BobSession";

export async function POST(req: NextRequest) {
  const parsed = await verifySessionCookie(req.headers.get("cookie"));

  if (parsed) {
    try {
      await connectToDatabase();
      await BobSession.deleteOne({ sessionId: parsed.sessionId });
    } catch {
      // Best effort cleanup.
    }
  }

  const res = NextResponse.json({ ok: true });
  res.headers.set("Set-Cookie", clearSessionCookie());
  return res;
}
