import { generateRegistrationOptions } from "@simplewebauthn/server";
import { NextRequest, NextResponse } from "next/server";
import { isAuthorizedEmail } from "@/lib/auth";
import { connectToDatabase } from "@/lib/db";
import { verifyOtpToken } from "@/lib/jwt-server";
import { getWebAuthnConfig } from "@/lib/webauthn-config";
import { BobAdmin } from "@/models/BobAdmin";
import { WebAuthnChallenge } from "@/models/WebAuthnChallenge";

const RP_NAME = process.env.NEXT_PUBLIC_WEBAUTHN_RP_NAME ?? "Bob Tester";

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
  const verifiedOtp = await verifyOtpToken(otpToken, email);
  if (!verifiedOtp) {
    return NextResponse.json({ error: "Invalid or expired OTP token" }, { status: 401 });
  }

  const { rpId } = getWebAuthnConfig(req);

  try {
    await connectToDatabase();

    if (!(await isAuthorizedEmail(email))) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }

    const doc = await BobAdmin.findOne({}, { passkeys: 1 }).lean();
    const existingPasskeys = (doc?.passkeys ?? []).filter(
      (passkey) => passkey.email === email && (!passkey.rpId || passkey.rpId === rpId)
    );

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: rpId,
      userName: email,
      userDisplayName: email,
      userID: Buffer.from(email),
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      excludeCredentials: existingPasskeys.map((passkey) => ({
        id: passkey.credentialID,
        transports: passkey.transports as AuthenticatorTransport[],
      })),
    });

    await WebAuthnChallenge.findOneAndUpdate(
      { email, type: "registration" },
      {
        $set: {
          challenge: options.challenge,
          email,
          type: "registration",
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );

    return NextResponse.json({ options });
  } catch (error) {
    console.error("POST /api/auth/webauthn/register/challenge", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
