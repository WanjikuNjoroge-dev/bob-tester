"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Script from "next/script";
import {
  Fingerprint,
  KeyRound,
  RotateCcw,
  Terminal,
  UserRound,
} from "lucide-react";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

type Step = "email" | "otp" | "passkey-auth" | "passkey-register";

function Spinner() {
  return <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-r-transparent" />;
}

export function LoginClient() {
  const router = useRouter();
  const recaptchaSiteKey = process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY ?? "";
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const passkeyName = "Primary Console";
  const [otpAttemptToken, setOtpAttemptToken] = useState("");
  const [otpToken, setOtpToken] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [sendCooldownSeconds, setSendCooldownSeconds] = useState(0);
  const [codeExpired, setCodeExpired] = useState(false);

  useEffect(() => {
    if (sendCooldownSeconds <= 0) {
      return;
    }

    const id = window.setInterval(() => {
      setSendCooldownSeconds((previous) => Math.max(0, previous - 1));
    }, 1000);

    return () => window.clearInterval(id);
  }, [sendCooldownSeconds]);

  function secondsUntil(iso?: string | null) {
    if (!iso) {
      return 0;
    }

    const millis = new Date(iso).getTime() - Date.now();
    return Math.max(0, Math.ceil(millis / 1000));
  }

  function resetOtpFlow() {
    setCode("");
    setError("");
    setOtpAttemptToken("");
    setOtpToken("");
    setSendCooldownSeconds(0);
    setCodeExpired(false);
  }

  async function getRecaptchaToken(action: "otp_send" | "otp_verify") {
    if (!recaptchaSiteKey || !window.grecaptcha) {
      throw new Error("Security check unavailable.");
    }

    return new Promise<string>((resolve, reject) => {
      window.grecaptcha?.ready(() => {
        window.grecaptcha
          ?.execute(recaptchaSiteKey, { action })
          .then(resolve)
          .catch(reject);
      });
    });
  }

  async function handleSendOtp(event?: React.FormEvent) {
    event?.preventDefault();
    setError("");
    setLoading(true);
    setCode("");
    setCodeExpired(false);

    try {
      const recaptchaToken = await getRecaptchaToken("otp_send");
      const res = await fetch("/api/auth/otp/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, recaptchaToken }),
      });
      const data = await res.json();

      if (!res.ok) {
        if (res.status === 429 && typeof data.retryAfterSeconds === "number") {
          setSendCooldownSeconds(data.retryAfterSeconds);
        }
        setError(data.error ?? "Failed to send code");
        return;
      }

      setOtpAttemptToken(data.otpAttemptToken ?? "");
      setSendCooldownSeconds(secondsUntil(data.resendAvailableAt));
      setStep("otp");
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerifyOtp(event: React.FormEvent) {
    event.preventDefault();
    setError("");

    if (!otpAttemptToken) {
      setError("Request a new verification code to continue.");
      return;
    }

    setLoading(true);

    try {
      const recaptchaToken = await getRecaptchaToken("otp_verify");
      const res = await fetch("/api/auth/otp/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code, otpAttemptToken, recaptchaToken }),
      });
      const data = await res.json();

      if (!res.ok) {
        if (data.codeExpired || data.attemptsRemaining === 0) {
          setCodeExpired(true);
        }
        if (res.status === 401) {
          setOtpAttemptToken("");
        }
        setError(data.error ?? "Invalid code");
        return;
      }

      setOtpToken(data.otpToken);
      setStep(data.hasPasskey ? "passkey-auth" : "passkey-register");
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  async function handlePasskeyAuth() {
    setError("");
    setLoading(true);

    try {
      const challengeRes = await fetch("/api/auth/webauthn/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otpToken }),
      });
      const challengeData = await challengeRes.json();

      if (!challengeRes.ok) {
        if (challengeData.needsRegistration) {
          setStep("passkey-register");
          return;
        }
        setError(challengeData.error ?? "Failed to get challenge");
        return;
      }

      const assertion = await startAuthentication({
        optionsJSON: challengeData.options as PublicKeyCredentialRequestOptionsJSON,
      });

      const verifyRes = await fetch("/api/auth/webauthn/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otpToken, response: assertion }),
      });
      const verifyData = await verifyRes.json();

      if (!verifyRes.ok) {
        setError(verifyData.error ?? "Authentication failed");
        return;
      }

      router.push("/");
    } catch (caught) {
      if (caught instanceof Error && caught.name === "NotAllowedError") {
        setError("Passkey authentication was cancelled.");
      } else {
        setError("Passkey authentication failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  async function handlePasskeyRegister(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const challengeRes = await fetch("/api/auth/webauthn/register/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otpToken }),
      });
      const challengeData = await challengeRes.json();

      if (!challengeRes.ok) {
        setError(challengeData.error ?? "Failed to get registration challenge");
        return;
      }

      const registration = await startRegistration({
        optionsJSON: challengeData.options as PublicKeyCredentialCreationOptionsJSON,
      });

      const verifyRes = await fetch("/api/auth/webauthn/register/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          passkeyName,
          response: registration,
          otpToken,
        }),
      });
      const verifyData = await verifyRes.json();

      if (!verifyRes.ok) {
        setError(verifyData.error ?? "Registration failed");
        return;
      }

      router.push("/");
    } catch (caught) {
      if (caught instanceof Error && caught.name === "NotAllowedError") {
        setError("Passkey registration was cancelled.");
      } else {
        setError("Passkey registration failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-[var(--bg)] text-[var(--text-primary)]">
      {recaptchaSiteKey ? (
        <Script
          id="recaptcha-v3"
          src={`https://www.google.com/recaptcha/api.js?render=${recaptchaSiteKey}`}
          strategy="afterInteractive"
        />
      ) : null}
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(113,255,173,0.06)_1px,transparent_1px),linear-gradient(90deg,rgba(113,255,173,0.06)_1px,transparent_1px)] bg-[size:2.6rem_2.6rem] opacity-50" />
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(48,255,128,0.13),transparent_45%),linear-gradient(180deg,rgba(3,10,8,0.24),rgba(3,10,8,0.88))]" />
      <div className="scanlines pointer-events-none absolute inset-0 opacity-30" />

      <main className="relative z-10 flex min-h-screen items-center justify-center px-5 py-10">
        <section className="w-full max-w-xl overflow-hidden border border-[var(--line-strong)] bg-[var(--panel)] shadow-[0_0_60px_rgba(7,255,122,0.06)]">
          <div className="relative flex min-h-[36rem] items-center bg-[linear-gradient(180deg,rgba(6,11,9,0.88),rgba(2,5,4,0.98))] px-5 py-7 sm:px-8 md:px-10">
            <div className="w-full">
              <div className="mb-8 border-b border-[var(--line-soft)] pb-5">
                <div className="mb-4 flex items-center gap-3 text-[var(--text-primary)]">
                  <div className="flex h-11 w-11 items-center justify-center border border-[var(--line-strong)] bg-[rgba(14,27,20,0.75)]">
                    <Terminal className="h-5 w-5 text-[var(--accent)]" />
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.36em] text-[var(--text-muted)]">
                      Bob Tester
                    </p>
                    <h1 className="text-2xl font-semibold uppercase tracking-[0.08em]">
                      Access
                    </h1>
                  </div>
                </div>
                <div className="h-px w-24 bg-[var(--line-strong)]" />
              </div>

              {step === "email" && (
                <form className="space-y-6" onSubmit={handleSendOtp}>
                  <div className="space-y-3">
                    <label className="block text-[11px] uppercase tracking-[0.28em] text-[var(--text-muted)]">
                      Identifier
                    </label>
                    <div className="relative">
                      <UserRound className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-[var(--text-muted)]" />
                      <input
                        type="email"
                        value={email}
                        onChange={(event) => setEmail(event.target.value)}
                        required
                        autoFocus
                        placeholder="name@example.com"
                        className="h-14 w-full border border-[var(--line-strong)] bg-[rgba(0,0,0,0.28)] pl-12 pr-4 font-mono text-sm text-[var(--text-primary)] outline-none transition focus:border-[var(--accent)]"
                      />
                    </div>
                  </div>

                  {error && <p className="text-sm text-[var(--error)]">{error}</p>}

                  <button
                    type="submit"
                    disabled={loading || !email || sendCooldownSeconds > 0}
                    className="inline-flex h-14 w-full items-center justify-center gap-3 border border-[var(--line-strong)] bg-[var(--accent)] px-5 text-sm font-semibold uppercase tracking-[0.22em] text-black transition hover:bg-[var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {loading ? <Spinner /> : <Terminal className="h-4 w-4" />}
                    {sendCooldownSeconds > 0 ? "Wait" : "Continue"}
                  </button>
                </form>
              )}

              {step === "otp" && (
                <form className="space-y-6" onSubmit={handleVerifyOtp}>
                  <div className="space-y-4">
                    <label className="block text-[11px] uppercase tracking-[0.28em] text-[var(--text-muted)]">
                      Code
                    </label>
                    <div className="relative">
                      <KeyRound className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-[var(--text-muted)]" />
                      <input
                        type="text"
                        inputMode="numeric"
                        pattern="\d{6}"
                        maxLength={6}
                        value={code}
                        onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))}
                        required
                        autoFocus
                        placeholder="000000"
                        className="h-14 w-full border border-[var(--line-strong)] bg-[rgba(0,0,0,0.28)] pl-12 pr-4 font-mono text-lg tracking-[0.32em] text-[var(--text-primary)] outline-none transition focus:border-[var(--accent)]"
                      />
                    </div>
                  </div>

                  {error && <p className="text-sm text-[var(--error)]">{error}</p>}

                  <button
                    type="submit"
                    disabled={loading || code.length !== 6 || codeExpired}
                    className="inline-flex h-14 w-full items-center justify-center gap-3 border border-[var(--line-strong)] bg-[var(--accent)] px-5 text-sm font-semibold uppercase tracking-[0.22em] text-black transition hover:bg-[var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {loading ? <Spinner /> : <Fingerprint className="h-4 w-4" />}
                    {codeExpired ? "Reset" : "Continue"}
                  </button>

                  <div className="flex flex-col gap-3 border-t border-[var(--line-soft)] pt-4 text-xs uppercase tracking-[0.24em] text-[var(--text-muted)] sm:flex-row sm:items-center sm:justify-between">
                    <button
                      type="button"
                      onClick={() => {
                        setStep("email");
                        resetOtpFlow();
                      }}
                      className="inline-flex items-center gap-2 text-left transition hover:text-[var(--text-primary)]"
                    >
                      <RotateCcw className="h-4 w-4" />
                      Back
                    </button>
                    {sendCooldownSeconds > 0 ? (
                      <span>Wait</span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => {
                          setCode("");
                          setError("");
                          void handleSendOtp();
                        }}
                        className="transition hover:text-[var(--accent)]"
                      >
                        Retry
                      </button>
                    )}
                  </div>
                </form>
              )}

              {step === "passkey-auth" && (
                <div className="space-y-6">
                  <div className="flex h-28 items-center justify-center border border-[var(--line-soft)] bg-black/20">
                    <Fingerprint className="h-10 w-10 text-[var(--accent)]" />
                  </div>

                  {error && <p className="text-sm text-[var(--error)]">{error}</p>}

                  <button
                    type="button"
                    onClick={handlePasskeyAuth}
                    disabled={loading}
                    className="inline-flex h-14 w-full items-center justify-center gap-3 border border-[var(--line-strong)] bg-[var(--accent)] px-5 text-sm font-semibold uppercase tracking-[0.22em] text-black transition hover:bg-[var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {loading ? <Spinner /> : <Fingerprint className="h-4 w-4" />}
                    Continue
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setStep("email");
                      resetOtpFlow();
                    }}
                    className="inline-flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-[var(--text-muted)] transition hover:text-[var(--text-primary)]"
                  >
                    <RotateCcw className="h-4 w-4" />
                    Back
                  </button>
                </div>
              )}

              {step === "passkey-register" && (
                <form className="space-y-6" onSubmit={handlePasskeyRegister}>
                  <div className="flex h-28 items-center justify-center border border-[var(--line-soft)] bg-black/20">
                    <Fingerprint className="h-10 w-10 text-[var(--accent)]" />
                  </div>

                  {error && <p className="text-sm text-[var(--error)]">{error}</p>}

                  <button
                    type="submit"
                    disabled={loading}
                    className="inline-flex h-14 w-full items-center justify-center gap-3 border border-[var(--line-strong)] bg-[var(--accent)] px-5 text-sm font-semibold uppercase tracking-[0.22em] text-black transition hover:bg-[var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {loading ? <Spinner /> : <Fingerprint className="h-4 w-4" />}
                    Continue
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setStep("email");
                      resetOtpFlow();
                    }}
                    className="inline-flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-[var(--text-muted)] transition hover:text-[var(--text-primary)]"
                  >
                    <RotateCcw className="h-4 w-4" />
                    Back
                  </button>
                </form>
              )}
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
