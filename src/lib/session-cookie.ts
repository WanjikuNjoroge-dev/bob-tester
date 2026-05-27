const COOKIE_NAME = "bob_tester_sess";
const SESSION_MAX_AGE = 8 * 60 * 60;

function hexToUint8Array(hex: string) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i += 1) {
    arr[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

async function getCryptoKey() {
  const keyHex = process.env.SESSION_HMAC_KEY ?? "";
  if (!keyHex) {
    throw new Error("SESSION_HMAC_KEY is not set.");
  }

  return crypto.subtle.importKey(
    "raw",
    hexToUint8Array(keyHex).buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

function base64urlEncode(data: Uint8Array) {
  let binary = "";
  for (let i = 0; i < data.length; i += 1) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(value: string) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const arr = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    arr[i] = binary.charCodeAt(i);
  }

  return arr;
}

async function sign(payload: string) {
  const key = await getCryptoKey();
  const encoded = new TextEncoder().encode(payload);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoded.buffer as ArrayBuffer
  );

  return base64urlEncode(new Uint8Array(signature));
}

async function buildCookieValue(email: string, sessionId: string) {
  const payload = base64urlEncode(
    new TextEncoder().encode(JSON.stringify({ e: email, s: sessionId }))
  );
  const signature = await sign(payload);
  return `${payload}.${signature}`;
}

export async function serializeSessionCookie(
  email: string,
  sessionId: string,
  maxAgeSeconds = SESSION_MAX_AGE
) {
  const value = await buildCookieValue(email, sessionId);
  const isProduction = process.env.NODE_ENV === "production";
  const parts = [
    `${COOKIE_NAME}=${value}`,
    "HttpOnly",
    "Path=/",
    `Max-Age=${maxAgeSeconds}`,
    "SameSite=Lax",
  ];

  if (isProduction) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

export async function verifySessionCookie(cookieHeader: string | null | undefined) {
  if (!cookieHeader) {
    return null;
  }

  const entry = cookieHeader
    .split(";")
    .map((segment) => segment.trim())
    .find((segment) => segment.startsWith(`${COOKIE_NAME}=`));

  if (!entry) {
    return null;
  }

  const value = entry.slice(COOKIE_NAME.length + 1);
  const dotIndex = value.lastIndexOf(".");
  if (dotIndex === -1) {
    return null;
  }

  const payload = value.slice(0, dotIndex);
  const signature = value.slice(dotIndex + 1);

  try {
    const key = await getCryptoKey();
    const signatureBytes = base64urlDecode(signature);
    const payloadBytes = new TextEncoder().encode(payload);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signatureBytes.buffer as ArrayBuffer,
      payloadBytes.buffer as ArrayBuffer
    );

    if (!valid) {
      return null;
    }

    const parsed = JSON.parse(
      new TextDecoder().decode(base64urlDecode(payload))
    ) as { e?: string; s?: string };

    if (typeof parsed.e !== "string" || typeof parsed.s !== "string") {
      return null;
    }

    return {
      email: parsed.e,
      sessionId: parsed.s,
    };
  } catch {
    return null;
  }
}

export function clearSessionCookie() {
  const isProduction = process.env.NODE_ENV === "production";
  const parts = [
    `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`,
  ];

  if (isProduction) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

export { COOKIE_NAME, SESSION_MAX_AGE };
