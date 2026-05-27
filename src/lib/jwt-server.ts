import { importJWK, jwtVerify } from "jose";

const ALG = "ES256";
export const JWT_ISSUER = process.env.JWT_ISSUER ?? "https://bobtester.local";

function getPublicKeyJwk(): Record<string, unknown> {
  const raw = process.env.JWT_PUBLIC_KEY_JWK ?? "";
  if (!raw) {
    throw new Error("JWT_PUBLIC_KEY_JWK is not set.");
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("JWT_PUBLIC_KEY_JWK is not valid JSON.");
  }
}

export async function verifyOtpToken(token: string, expectedEmail: string) {
  try {
    const publicKey = await importJWK(getPublicKeyJwk(), ALG);
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: JWT_ISSUER,
      audience: "otp-registration",
    });

    const parsed = payload as {
      purpose?: string;
      email?: string;
      sub?: string;
    };

    return (
      parsed.purpose === "otp-verified" &&
      (parsed.email === expectedEmail || parsed.sub === expectedEmail)
    );
  } catch {
    return false;
  }
}

export async function verifyOtpAttemptToken(
  token: string,
  expectedEmail: string
) {
  try {
    const publicKey = await importJWK(getPublicKeyJwk(), ALG);
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: JWT_ISSUER,
      audience: "otp-verification",
    });

    const parsed = payload as {
      purpose?: string;
      email?: string;
      sub?: string;
      jti?: string;
    };
    const email = parsed.email ?? parsed.sub;

    if (
      parsed.purpose !== "otp-attempt" ||
      email !== expectedEmail ||
      !parsed.jti
    ) {
      return null;
    }

    return {
      email,
      jti: parsed.jti,
    };
  } catch {
    return null;
  }
}
