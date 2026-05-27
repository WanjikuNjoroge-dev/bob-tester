import { cookies } from "next/headers";
import type { NextRequest } from "next/server";
import { connectToDatabase } from "./db";
import { verifySessionCookie } from "./session-cookie";
import { BobSession, type AdminRole } from "@/models/BobSession";

export class AuthError extends Error {
  constructor(
    public readonly status: 401 | 403,
    message: string
  ) {
    super(message);
  }
}

export function resolveRole(email: string): AdminRole {
  const superAdminEmail = (process.env.SUPER_ADMIN_EMAIL ?? "")
    .trim()
    .toLowerCase();
  if (!superAdminEmail) {
    throw new Error("SUPER_ADMIN_EMAIL is not set.");
  }
  return email.toLowerCase() === superAdminEmail ? "super_admin" : "admin";
}

export async function getSessionFromCookieHeader(
  cookieHeader: string | null | undefined
) {
  const parsed = await verifySessionCookie(cookieHeader);
  if (!parsed) {
    return null;
  }

  await connectToDatabase();
  const session = await BobSession.findOne({ sessionId: parsed.sessionId }).lean();
  if (!session || new Date(session.expiresAt) < new Date()) {
    return null;
  }

  return session;
}

export async function getCurrentSession() {
  const cookieStore = await cookies();
  const cookieHeader = cookieStore
    .getAll()
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join("; ");

  return getSessionFromCookieHeader(cookieHeader);
}

export async function requireAuth(req: NextRequest) {
  const session = await getSessionFromCookieHeader(req.headers.get("cookie"));
  if (!session) {
    throw new AuthError(401, "Unauthorized");
  }

  return {
    email: session.email,
    role: session.role,
  };
}
