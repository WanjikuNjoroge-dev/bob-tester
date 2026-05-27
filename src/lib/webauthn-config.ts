import type { NextRequest } from "next/server";

export function getWebAuthnConfig(req: NextRequest) {
  const host = req.headers.get("host") ?? "localhost:3000";
  const rpId = host.split(":")[0];
  const forwardedProto = req.headers.get("x-forwarded-proto");
  const isLocalhost = rpId === "localhost" || rpId === "127.0.0.1";
  const protocol = forwardedProto ?? (isLocalhost ? "http" : "https");

  return {
    rpId,
    rpOrigin: `${protocol}://${host}`,
  };
}
