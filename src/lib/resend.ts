import { Resend } from "resend";

export function getResendClient() {
  const apiKey = process.env.RESEND_API_KEY ?? "";
  if (!apiKey) {
    throw new Error("RESEND_API_KEY is not set.");
  }

  return new Resend(apiKey);
}

export function getResendFromEmail() {
  const fromEmail = process.env.RESEND_FROM_EMAIL ?? "";
  if (!fromEmail) {
    throw new Error("RESEND_FROM_EMAIL is not set.");
  }

  return fromEmail;
}
