import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { NextRequest, NextResponse } from "next/server";
import { resolveRole } from "@/lib/auth";
import { connectToDatabase } from "@/lib/db";
import { verifyOtpToken } from "@/lib/jwt-server";
import { serializeSessionCookie } from "@/lib/session-cookie";
import { getWebAuthnConfig } from "@/lib/webauthn-config";
import { BobAdmin } from "@/models/BobAdmin";
import { BobSession } from "@/models/BobSession";
import { WebAuthnChallenge } from "@/models/WebAuthnChallenge";

const SESSION_MAX_AGE_SECS = 8 * 60 * 60;

export async function POST(req: NextRequest) {
  const body = (await req.json().catch(() => ({}))) as {
    email?: string;
    passkeyName?: string;
    response?: RegistrationResponseJSON;
    otpToken?: string;
  };

  const { email: rawEmail, passkeyName, response, otpToken } = body;

  if (!rawEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail.trim())) {
    return NextResponse.json({ error: "Valid email required" }, { status: 400 });
  }

  if (!response) {
    return NextResponse.json({ error: "response required" }, { status: 400 });
  }

  if (!otpToken) {
    return NextResponse.json({ error: "otpToken required" }, { status: 401 });
  }

  const email = rawEmail.trim().toLowerCase();
  const validToken = await verifyOtpToken(otpToken, email);
  if (!validToken) {
    return NextResponse.json({ error: "Invalid or expired OTP token" }, { status: 401 });
  }

  const { rpId, rpOrigin } = getWebAuthnConfig(req);

  try {
    await connectToDatabase();

    const challengeDoc = await WebAuthnChallenge.findOneAndDelete({
      email,
      type: "registration",
    });

    if (!challengeDoc) {
      return NextResponse.json(
        { error: "No pending registration challenge. Start over." },
        { status: 400 }
      );
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challengeDoc.challenge,
      expectedOrigin: rpOrigin,
      expectedRPID: rpId,
      requireUserVerification: true,
    }).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : "unknown";
      return { error: message };
    });

    if ("error" in verification) {
      return NextResponse.json(
        { error: `Verification failed: ${verification.error}` },
        { status: 400 }
      );
    }

    if (!verification.verified || !verification.registrationInfo) {
      return NextResponse.json(
        { error: "Passkey registration could not be verified" },
        { status: 400 }
      );
    }

    const credential = verification.registrationInfo.credential;
    const duplicate = await BobAdmin.findOne(
      { "passkeys.credentialID": credential.id },
      { _id: 1 }
    ).lean();

    if (duplicate) {
      return NextResponse.json(
        { error: "This passkey is already registered" },
        { status: 409 }
      );
    }

    await BobAdmin.findOneAndUpdate(
      {},
      {
        $push: {
          passkeys: {
            email,
            credentialID: credential.id,
            credentialPublicKey: Buffer.from(credential.publicKey).toString("base64url"),
            counter: credential.counter,
            transports: (credential.transports as string[]) ?? [],
            name: passkeyName?.trim() || "Passkey",
            rpId,
            addedAt: new Date(),
          },
        },
      },
      { upsert: true }
    );

    const sessionId = crypto.randomUUID();
    const role = resolveRole(email);
    const expiresAt = new Date(Date.now() + SESSION_MAX_AGE_SECS * 1000);

    await BobSession.create({ sessionId, email, role, expiresAt });

    const res = NextResponse.json({ ok: true });
    res.headers.set(
      "Set-Cookie",
      await serializeSessionCookie(email, sessionId, SESSION_MAX_AGE_SECS)
    );
    return res;
  } catch (error) {
    console.error("POST /api/auth/webauthn/register/verify", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
