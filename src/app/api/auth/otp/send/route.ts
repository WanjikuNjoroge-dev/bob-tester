import { randomInt } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { connectToDatabase } from "@/lib/db";
import { isDisposableEmail } from "@/lib/email-policy";
import { hashOtpCode, hashOtpRateLimitKey, signOtpAttemptToken } from "@/lib/otp-server";
import { verifyRecaptchaToken } from "@/lib/recaptcha";
import { getResendClient, getResendFromEmail } from "@/lib/resend";
import { OtpChallenge } from "@/models/OtpChallenge";
import { OtpRateLimit } from "@/models/OtpRateLimit";

const RESEND_GAP_MS = 60 * 1000;
const SEND_LIMIT = 2;
const SEND_WINDOW_MS = 10 * 60 * 1000;
const COOLDOWN_MS = 30 * 60 * 1000;

function generateCode() {
  return String(randomInt(100000, 1000000)).padStart(6, "0");
}

function formatRetryAfter(seconds: number) {
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;

  if (minutes <= 0) {
    return `${remainder}s`;
  }

  if (remainder === 0) {
    return `${minutes}m`;
  }

  return `${minutes}m ${remainder}s`;
}

function getRetryAfterSeconds(until: Date) {
  return Math.max(1, Math.ceil((until.getTime() - Date.now()) / 1000));
}

function buildSendSuccessPayload(args: {
  otpAttemptToken: string;
  emailSendsRemaining: number;
  resendAvailableAt: Date;
}) {
  return {
    ok: true,
    otpAttemptToken: args.otpAttemptToken,
    emailSendsRemaining: args.emailSendsRemaining,
    resendAvailableAt: args.resendAvailableAt.toISOString(),
  };
}

function sendLimitResponse(args: {
  message: string;
  cooldownUntil: Date;
  limitScope: "email-send" | "resend";
  emailSendsRemaining: number;
  resendAvailableAt: Date | null;
}) {
  const retryAfterSeconds = getRetryAfterSeconds(args.cooldownUntil);

  return NextResponse.json(
    {
      error: `${args.message} Try again in ${formatRetryAfter(retryAfterSeconds)}.`,
      cooldownUntil: args.cooldownUntil.toISOString(),
      retryAfterSeconds,
      limitScope: args.limitScope,
      emailSendsRemaining: args.emailSendsRemaining,
      resendAvailableAt: args.resendAvailableAt?.toISOString() ?? null,
    },
    {
      status: 429,
      headers: { "Retry-After": String(retryAfterSeconds) },
    }
  );
}

async function loadEmailSendLimiter(emailHash: string, now: Date) {
  const limiter = await OtpRateLimit.findOneAndUpdate(
    { scope: "email_send", emailHash },
    {
      $setOnInsert: {
        scope: "email_send",
        jti: null,
        emailHash,
        ipHash: null,
        attempts: 0,
        windowStartedAt: now,
        lastAttemptAt: null,
        cooldownUntil: null,
      },
    },
    { upsert: true, returnDocument: "after" }
  );

  if (!limiter) {
    throw new Error("Failed to load OTP send limiter.");
  }

  return limiter;
}

export async function POST(req: NextRequest) {
  const body = (await req.json().catch(() => ({}))) as {
    email?: string;
    recaptchaToken?: string;
  };
  const rawEmail = body.email;

  if (!rawEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail.trim())) {
    return NextResponse.json({ error: "Valid email required" }, { status: 400 });
  }

  const email = rawEmail.trim().toLowerCase();

  if (isDisposableEmail(email)) {
    return NextResponse.json({ error: "Email not allowed" }, { status: 400 });
  }

  try {
    const recaptcha = await verifyRecaptchaToken({
      req,
      token: body.recaptchaToken,
      action: "otp_send",
    });
    if (!recaptcha.ok) {
      return NextResponse.json({ error: recaptcha.error }, { status: recaptcha.status });
    }

    const otpAttemptToken = await signOtpAttemptToken(email, recaptcha.binding);
    await connectToDatabase();

    const now = new Date();
    const emailHash = hashOtpRateLimitKey(`email:${email}`);
    const limiter = await loadEmailSendLimiter(emailHash, now);

    if (limiter.cooldownUntil && limiter.cooldownUntil.getTime() > now.getTime()) {
      return sendLimitResponse({
        message: "Too many verification code requests.",
        cooldownUntil: limiter.cooldownUntil,
        limitScope: "email-send",
        emailSendsRemaining: 0,
        resendAvailableAt: limiter.lastAttemptAt
          ? new Date(limiter.lastAttemptAt.getTime() + RESEND_GAP_MS)
          : null,
      });
    }

    const windowExpired =
      now.getTime() - new Date(limiter.windowStartedAt).getTime() >= SEND_WINDOW_MS;

    if (windowExpired) {
      limiter.attempts = 0;
      limiter.windowStartedAt = now;
      limiter.cooldownUntil = null;
    }

    const resendAvailableAt = limiter.lastAttemptAt
      ? new Date(limiter.lastAttemptAt.getTime() + RESEND_GAP_MS)
      : null;

    if (resendAvailableAt && resendAvailableAt.getTime() > now.getTime()) {
      return sendLimitResponse({
        message: "Please wait before requesting another code.",
        cooldownUntil: resendAvailableAt,
        limitScope: "resend",
        emailSendsRemaining: Math.max(0, SEND_LIMIT - limiter.attempts),
        resendAvailableAt,
      });
    }

    if (limiter.attempts >= SEND_LIMIT) {
      limiter.cooldownUntil = new Date(now.getTime() + COOLDOWN_MS);
      await limiter.save();

      return sendLimitResponse({
        message: "Too many verification code requests.",
        cooldownUntil: limiter.cooldownUntil,
        limitScope: "email-send",
        emailSendsRemaining: 0,
        resendAvailableAt,
      });
    }

    limiter.attempts += 1;
    limiter.lastAttemptAt = now;
    limiter.cooldownUntil = null;
    await limiter.save();

    const payload = buildSendSuccessPayload({
      otpAttemptToken,
      emailSendsRemaining: Math.max(0, SEND_LIMIT - limiter.attempts),
      resendAvailableAt: new Date(now.getTime() + RESEND_GAP_MS),
    });

    const code = generateCode();
    const codeHash = hashOtpCode(code);

    await OtpChallenge.findOneAndUpdate(
      { email },
      { $set: { codeHash, createdAt: now } },
      { upsert: true }
    );

    const resend = getResendClient();
    const { data, error } = await resend.emails.send(
      {
        from: `Bob Tester <${getResendFromEmail()}>`,
        to: [email],
        subject: "Bob Tester verification code",
        text: [
          "Your Bob Tester verification code is:",
          code,
          "",
          "This code expires in 10 minutes.",
          "",
          "If you did not request this code, you can ignore this message.",
        ].join("\n"),
      },
      {
        idempotencyKey: `otp-send/${emailHash}/${now.getTime()}`,
      }
    );

    if (error) {
      console.error("POST /api/auth/otp/send resend error", error);
      return NextResponse.json(
        { error: "Unable to send code right now." },
        { status: 502 }
      );
    }

    if (!data?.id) {
      console.error("POST /api/auth/otp/send missing resend id");
      return NextResponse.json(
        { error: "Unable to send code right now." },
        { status: 502 }
      );
    }

    return NextResponse.json(payload);
  } catch (error) {
    console.error("POST /api/auth/otp/send", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
