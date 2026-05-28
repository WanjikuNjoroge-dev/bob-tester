import { createHmac } from "node:crypto";
import type { NextRequest } from "next/server";

type RecaptchaAction = "otp_send" | "otp_verify";

type RecaptchaVerifyResponse = {
  success?: boolean;
  score?: number;
  action?: string;
  hostname?: string;
  challenge_ts?: string;
  "error-codes"?: string[];
};

function getSecretKey() {
  const secret = process.env.RECAPTCHA_SECRET_KEY ?? "";
  if (!secret) {
    throw new Error("RECAPTCHA_SECRET_KEY is not set.");
  }
  return secret;
}

function buildRecaptchaBinding(parts: string[]) {
  return createHmac("sha256", getSecretKey()).update(parts.join("|")).digest("hex");
}

function getScoreThreshold() {
  const raw = process.env.RECAPTCHA_MIN_SCORE ?? "0.5";
  const parsed = Number.parseFloat(raw);
  if (Number.isNaN(parsed)) {
    return 0.5;
  }
  return parsed;
}

function getClientIp(req: NextRequest) {
  const forwardedFor = req.headers.get("x-forwarded-for");
  if (forwardedFor) {
    return forwardedFor.split(",")[0].trim() || "";
  }

  return req.headers.get("x-real-ip")?.trim() || "";
}

export async function verifyRecaptchaToken(args: {
  req: NextRequest;
  token?: string;
  action: RecaptchaAction;
}) {
  const token = args.token?.trim();
  if (!token) {
    return { ok: false as const, status: 400, error: "Security check failed" };
  }

  const body = new URLSearchParams({
    secret: getSecretKey(),
    response: token,
  });

  const remoteIp = getClientIp(args.req);
  if (remoteIp) {
    body.set("remoteip", remoteIp);
  }

  const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: body.toString(),
    cache: "no-store",
  });

  if (!response.ok) {
    return { ok: false as const, status: 502, error: "Security check unavailable" };
  }

  const data = (await response.json()) as RecaptchaVerifyResponse;

  if (!data.success) {
    return { ok: false as const, status: 400, error: "Security check failed" };
  }

  if (data.action !== args.action) {
    return { ok: false as const, status: 400, error: "Security check failed" };
  }

  if (typeof data.score !== "number" || data.score < getScoreThreshold()) {
    return { ok: false as const, status: 403, error: "Request blocked" };
  }

  const binding = buildRecaptchaBinding([
    token,
    args.action,
    String(data.score),
    data.hostname ?? "",
    data.challenge_ts ?? "",
  ]);

  return { ok: true as const, binding };
}

export function mergeRecaptchaBindings(bindings: string[]) {
  return buildRecaptchaBinding(bindings);
}
