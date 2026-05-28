import { timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { isAuthorizedEmail } from "@/lib/auth";
import { connectToDatabase } from "@/lib/db";
import { isDisposableEmail } from "@/lib/email-policy";
import { verifyOtpAttemptToken } from "@/lib/jwt-server";
import { hashOtpCode, hashOtpRateLimitKey, signOtpToken } from "@/lib/otp-server";
import { mergeRecaptchaBindings, verifyRecaptchaToken } from "@/lib/recaptcha";
import { getWebAuthnConfig } from "@/lib/webauthn-config";
import { BobAdmin } from "@/models/BobAdmin";
import { OtpChallenge } from "@/models/OtpChallenge";
import { OtpRateLimit } from "@/models/OtpRateLimit";

const ATTEMPT_LIMIT = 3;
const ATTEMPT_WINDOW_MS = 5 * 60 * 1000;

function getClientIp(req: NextRequest) {
  const forwardedFor = req.headers.get("x-forwarded-for");
  if (forwardedFor) {
    return forwardedFor.split(",")[0].trim() || "unknown";
  }

  return req.headers.get("x-real-ip")?.trim() || "unknown";
}

async function getAttemptLimiter(args: {
  emailHash: string;
  jti: string;
  ipHash: string;
  now: Date;
}) {
  const limiter = await OtpRateLimit.findOneAndUpdate(
    { scope: "attempt_ip", jti: args.jti, ipHash: args.ipHash },
    {
      $setOnInsert: {
        scope: "attempt_ip",
        jti: args.jti,
        emailHash: args.emailHash,
        ipHash: args.ipHash,
        attempts: 0,
        windowStartedAt: args.now,
        lastAttemptAt: null,
        cooldownUntil: null,
      },
    },
    { upsert: true, returnDocument: "after" }
  );

  if (!limiter) {
    throw new Error("Failed to load OTP attempt limiter.");
  }

  const windowExpired =
    args.now.getTime() - new Date(limiter.windowStartedAt).getTime() > ATTEMPT_WINDOW_MS;

  if (windowExpired) {
    limiter.attempts = 0;
    limiter.windowStartedAt = args.now;
    limiter.lastAttemptAt = null;
    limiter.cooldownUntil = null;
    await limiter.save();
  }

  return limiter;
}

async function recordFailedOtpAttempt(args: {
  emailHash: string;
  jti: string;
  ipHash: string;
}) {
  const now = new Date();
  const limiter = await getAttemptLimiter({ ...args, now });

  if (limiter.attempts >= ATTEMPT_LIMIT) {
    return { attemptsRemaining: 0, codeExpired: true };
  }

  limiter.attempts += 1;
  limiter.lastAttemptAt = now;
  limiter.cooldownUntil = null;
  await limiter.save();

  const attemptsRemaining = Math.max(0, ATTEMPT_LIMIT - limiter.attempts);
  return {
    attemptsRemaining,
    codeExpired: attemptsRemaining === 0,
  };
}

async function getAttemptsRemaining(args: {
  emailHash: string;
  jti: string;
  ipHash: string;
}) {
  const limiter = await OtpRateLimit.findOne(
    { scope: "attempt_ip", jti: args.jti, ipHash: args.ipHash },
    { attempts: 1 }
  ).lean();

  return Math.max(0, ATTEMPT_LIMIT - (limiter?.attempts ?? 0));
}

async function clearAttemptLimiter(args: { jti: string; ipHash: string }) {
  await OtpRateLimit.deleteOne({
    scope: "attempt_ip",
    jti: args.jti,
    ipHash: args.ipHash,
  });
}

async function expireCurrentCode(args: { email: string; challengeId?: unknown }) {
  if (args.challengeId) {
    await OtpChallenge.deleteOne({ _id: args.challengeId });
    return;
  }

  await OtpChallenge.deleteOne({ email: args.email });
}

export async function POST(req: NextRequest) {
  const body = (await req.json().catch(() => ({}))) as {
    email?: string;
    code?: string;
    otpAttemptToken?: string;
    recaptchaToken?: string;
  };

  const { email: rawEmail, code, otpAttemptToken } = body;

  if (!rawEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail.trim())) {
    return NextResponse.json({ error: "Valid email required" }, { status: 400 });
  }

  if (!code || !/^\d{6}$/.test(code)) {
    return NextResponse.json({ error: "6-digit code required" }, { status: 400 });
  }

  if (!otpAttemptToken) {
    return NextResponse.json(
      { error: "Verification session required. Please request a new code." },
      { status: 401 }
    );
  }

  const email = rawEmail.trim().toLowerCase();
  if (isDisposableEmail(email)) {
    return NextResponse.json({ error: "Email not allowed" }, { status: 400 });
  }

  const attempt = await verifyOtpAttemptToken(otpAttemptToken, email);
  if (!attempt) {
    return NextResponse.json(
      {
        error: "Invalid or expired verification session. Please request a new code.",
      },
      { status: 401 }
    );
  }

  const ip = getClientIp(req);
  const emailHash = hashOtpRateLimitKey(`email:${email}`);
  const ipHash = hashOtpRateLimitKey(`ip:${ip}`);

  try {
    const recaptcha = await verifyRecaptchaToken({
      req,
      token: body.recaptchaToken,
      action: "otp_verify",
    });
    if (!recaptcha.ok) {
      return NextResponse.json({ error: recaptcha.error }, { status: recaptcha.status });
    }

    await connectToDatabase();

    const existingLimiter = await getAttemptLimiter({
      emailHash,
      jti: attempt.jti,
      ipHash,
      now: new Date(),
    });

    if (existingLimiter.attempts >= ATTEMPT_LIMIT) {
      return NextResponse.json(
        {
          error: "This code has expired. Request a new code to continue.",
          attemptsRemaining: 0,
          codeExpired: true,
        },
        { status: 400 }
      );
    }

    const challenge = await OtpChallenge.findOne({ email });
    if (!challenge) {
      const failedAttempt = await recordFailedOtpAttempt({
        emailHash,
        jti: attempt.jti,
        ipHash,
      });

      return NextResponse.json(
        {
          error: failedAttempt.codeExpired
            ? "This code has expired. Request a new code to continue."
            : "Invalid or expired code",
          attemptsRemaining: failedAttempt.attemptsRemaining,
          codeExpired: failedAttempt.codeExpired,
        },
        { status: 400 }
      );
    }

    const expected = hashOtpCode(code);
    const expectedBuffer = Buffer.from(expected, "utf8");
    const actualBuffer = Buffer.from(challenge.codeHash, "utf8");
    const matches =
      expectedBuffer.length === actualBuffer.length &&
      timingSafeEqual(expectedBuffer, actualBuffer);

    if (!matches) {
      const failedAttempt = await recordFailedOtpAttempt({
        emailHash,
        jti: attempt.jti,
        ipHash,
      });

      if (failedAttempt.codeExpired) {
        await expireCurrentCode({ email, challengeId: challenge._id });
      }

      return NextResponse.json(
        {
          error: failedAttempt.codeExpired
            ? "This code has expired. Request a new code to continue."
            : "Invalid or expired code",
          attemptsRemaining: failedAttempt.attemptsRemaining,
          codeExpired: failedAttempt.codeExpired,
        },
        { status: 400 }
      );
    }

    const attemptsRemaining = await getAttemptsRemaining({
      emailHash,
      jti: attempt.jti,
      ipHash,
    });

    const authorized = await isAuthorizedEmail(email);
    await OtpChallenge.deleteOne({ _id: challenge._id });
    await clearAttemptLimiter({ jti: attempt.jti, ipHash });

    if (!authorized) {
      return NextResponse.json(
        { error: "Access denied" },
        { status: 403 }
      );
    }

    const recaptchaBinding = mergeRecaptchaBindings([
      attempt.recaptchaBinding,
      recaptcha.binding,
    ]);
    const otpToken = await signOtpToken(email, recaptchaBinding);

    const { rpId } = getWebAuthnConfig(req);
    const doc = await BobAdmin.findOne(
      {
        "passkeys.email": email,
        $or: [
          { "passkeys.rpId": rpId },
          { "passkeys.rpId": null },
          { "passkeys.rpId": { $exists: false } },
        ],
      },
      { "passkeys.$": 1 }
    ).lean();

    return NextResponse.json({
      otpToken,
      hasPasskey: !!doc?.passkeys?.length,
      attemptsRemaining,
    });
  } catch (error) {
    console.error("POST /api/auth/otp/verify", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
