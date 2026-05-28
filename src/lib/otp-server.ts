import { createHmac, randomUUID } from "node:crypto";
import { importPKCS8, SignJWT } from "jose";
import { JWT_ISSUER } from "./jwt-server";

const ALG = "ES256";

function getOtpHmacKey() {
  const key = process.env.OTP_HMAC_KEY ?? "";
  if (!key) {
    throw new Error("OTP_HMAC_KEY is not set.");
  }
  return key;
}

function getPrivateKeyPem() {
  const raw = process.env.JWT_PRIVATE_KEY ?? "";
  if (!raw) {
    throw new Error("JWT_PRIVATE_KEY is not set.");
  }
  if (raw.startsWith("-----BEGIN")) {
    return raw.replace(/\\n/g, "\n");
  }
  return Buffer.from(raw, "base64").toString("utf8");
}

export function hashOtpCode(code: string) {
  return createHmac("sha256", getOtpHmacKey()).update(code).digest("hex");
}

export function hashOtpRateLimitKey(value: string) {
  return createHmac("sha256", getOtpHmacKey()).update(value).digest("hex");
}

export async function signOtpAttemptToken(email: string, recaptchaBinding: string) {
  const privateKey = await importPKCS8(getPrivateKeyPem(), ALG);
  return new SignJWT({ purpose: "otp-attempt", email, rb: recaptchaBinding })
    .setProtectedHeader({ alg: ALG, kid: "1" })
    .setSubject(email)
    .setJti(randomUUID())
    .setIssuedAt()
    .setIssuer(JWT_ISSUER)
    .setAudience("otp-verification")
    .setExpirationTime("10m")
    .sign(privateKey);
}

export async function signOtpToken(email: string, recaptchaBinding: string) {
  const privateKey = await importPKCS8(getPrivateKeyPem(), ALG);
  return new SignJWT({ purpose: "otp-verified", email, rb: recaptchaBinding })
    .setProtectedHeader({ alg: ALG, kid: "1" })
    .setSubject(email)
    .setIssuedAt()
    .setIssuer(JWT_ISSUER)
    .setAudience("otp-registration")
    .setExpirationTime("10m")
    .sign(privateKey);
}
