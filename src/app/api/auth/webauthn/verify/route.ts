import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { NextRequest, NextResponse } from "next/server";
import { resolveRole } from "@/lib/auth";
import { connectToDatabase } from "@/lib/db";
import { serializeSessionCookie } from "@/lib/session-cookie";
import { getWebAuthnConfig } from "@/lib/webauthn-config";
import { BobAdmin } from "@/models/BobAdmin";
import { BobSession } from "@/models/BobSession";
import { WebAuthnChallenge } from "@/models/WebAuthnChallenge";

const SESSION_MAX_AGE_SECS = 8 * 60 * 60;

export async function POST(req: NextRequest) {
  const body = (await req.json().catch(() => ({}))) as {
    email?: string;
    response?: AuthenticationResponseJSON;
  };

  const { email: rawEmail, response } = body;

  if (!rawEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail.trim())) {
    return NextResponse.json({ error: "Valid email required" }, { status: 400 });
  }

  if (!response) {
    return NextResponse.json({ error: "response required" }, { status: 400 });
  }

  const email = rawEmail.trim().toLowerCase();
  const { rpId, rpOrigin } = getWebAuthnConfig(req);

  try {
    await connectToDatabase();

    const challengeDoc = await WebAuthnChallenge.findOneAndDelete({
      email,
      type: "authentication",
    });

    if (!challengeDoc) {
      return NextResponse.json(
        { error: "No pending authentication challenge. Start over." },
        { status: 400 }
      );
    }

    const doc = await BobAdmin.findOne({ "passkeys.credentialID": response.id }).lean();
    if (!doc) {
      return NextResponse.json({ error: "Passkey not found" }, { status: 401 });
    }

    const passkey = doc.passkeys.find(
      (entry) => entry.credentialID === response.id && entry.email === email
    );

    if (!passkey) {
      return NextResponse.json(
        { error: "Passkey not found for this account" },
        { status: 401 }
      );
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeDoc.challenge,
      expectedOrigin: rpOrigin,
      expectedRPID: rpId,
      credential: {
        id: passkey.credentialID,
        publicKey: Buffer.from(passkey.credentialPublicKey, "base64url"),
        counter: passkey.counter,
        transports: passkey.transports as AuthenticatorTransport[],
      },
      requireUserVerification: true,
    }).catch((error: unknown) => {
      console.error("[webauthn/verify] verification error:", error);
      return null;
    });

    if (!verification?.verified) {
      return NextResponse.json(
        { error: "Passkey authentication could not be verified" },
        { status: 401 }
      );
    }

    await BobAdmin.updateOne(
      { "passkeys.credentialID": passkey.credentialID },
      {
        $set: {
          "passkeys.$.counter": verification.authenticationInfo.newCounter,
        },
      }
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
    console.error("POST /api/auth/webauthn/verify", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
