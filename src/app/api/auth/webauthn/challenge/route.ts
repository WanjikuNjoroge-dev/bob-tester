import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { NextRequest, NextResponse } from "next/server";
import { connectToDatabase } from "@/lib/db";
import { verifyOtpToken } from "@/lib/jwt-server";
import { getWebAuthnConfig } from "@/lib/webauthn-config";
import { BobAdmin } from "@/models/BobAdmin";
import { WebAuthnChallenge } from "@/models/WebAuthnChallenge";

const CHALLENGE_COOLDOWN_MS = 30_000;

export async function POST(req: NextRequest) {
  const body = (await req.json().catch(() => ({}))) as {
    email?: string;
    otpToken?: string;
  };

  const { email: rawEmail, otpToken } = body;

  if (!rawEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail.trim())) {
    return NextResponse.json({ error: "Valid email required" }, { status: 400 });
  }

  if (!otpToken) {
    return NextResponse.json({ error: "otpToken required" }, { status: 401 });
  }

  const email = rawEmail.trim().toLowerCase();
  const valid = await verifyOtpToken(otpToken, email);
  if (!valid) {
    return NextResponse.json({ error: "Invalid or expired OTP token" }, { status: 401 });
  }

  const { rpId } = getWebAuthnConfig(req);

  try {
    await connectToDatabase();

    const doc = await BobAdmin.findOne({}, { passkeys: 1 }).lean();
    const adminPasskeys = (doc?.passkeys ?? []).filter(
      (passkey) => passkey.email === email && (!passkey.rpId || passkey.rpId === rpId)
    );

    if (adminPasskeys.length === 0) {
      return NextResponse.json({ needsRegistration: true });
    }

    const recentChallenge = await WebAuthnChallenge.findOne(
      { email, type: "authentication" },
      { createdAt: 1 }
    ).lean();

    if (recentChallenge?.createdAt) {
      const age = Date.now() - new Date(recentChallenge.createdAt).getTime();
      if (age < CHALLENGE_COOLDOWN_MS) {
        const waitSeconds = Math.ceil((CHALLENGE_COOLDOWN_MS - age) / 1000);
        return NextResponse.json(
          { error: `Please wait ${waitSeconds} seconds before requesting a new challenge` },
          { status: 429 }
        );
      }
    }

    const options = await generateAuthenticationOptions({
      rpID: rpId,
      userVerification: "required",
      allowCredentials: adminPasskeys.map((passkey) => ({
        id: passkey.credentialID,
        transports: passkey.transports as AuthenticatorTransport[],
      })),
    });

    await WebAuthnChallenge.findOneAndUpdate(
      { email, type: "authentication" },
      {
        $set: {
          challenge: options.challenge,
          email,
          type: "authentication",
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );

    return NextResponse.json({ options });
  } catch (error) {
    console.error("POST /api/auth/webauthn/challenge", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
