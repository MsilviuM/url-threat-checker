"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { LogIn, ShieldCheck, KeyRound, CheckCircle } from "lucide-react";
import { Panel } from "@/components/panel";
import { login, verify2fa, resetPassword } from "@/lib/api";

type Step = "password" | "totp" | "reset" | "reset-done";

export default function LoginPage() {
  const router = useRouter();
  const [step, setStep] = useState<Step>("password");

  // password step
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");

  // totp step
  const [totpCode, setTotpCode] = useState("");

  // reset step
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [verificationCode, setVerificationCode] = useState("");

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const totpRef = useRef<HTMLInputElement>(null);
  const verificationCodeRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (step === "totp") totpRef.current?.focus();
    if (step === "reset") verificationCodeRef.current?.focus();
  }, [step]);

  function goTo(next: Step) {
    setError(null);
    setStep(next);
  }

  async function submitPassword(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await login(username, password);
      result.requires_2fa ? goTo("totp") : router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed.");
    } finally {
      setLoading(false);
    }
  }

  async function submitTotp(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await verify2fa(totpCode);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid code.");
      setTotpCode("");
      totpRef.current?.focus();
    } finally {
      setLoading(false);
    }
  }

  async function submitReset(e: FormEvent) {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await resetPassword(newPassword, verificationCode);
      goTo("reset-done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reset failed.");
      setVerificationCode("");
      verificationCodeRef.current?.focus();
    } finally {
      setLoading(false);
    }
  }

  // ── Reset success ────────────────────────────────────────────────────────────
  if (step === "reset-done") {
    return (
      <div className="mx-auto max-w-md pt-12">
        <Panel className="ui-elevated">
          <div className="mb-6 flex flex-col items-center gap-3 text-center">
            <CheckCircle className="size-10 text-green-500" />
            <h1 className="text-2xl font-semibold ui-heading">Password updated</h1>
            <p className="text-sm ui-muted">Your new password is active. Sign in to continue.</p>
          </div>
          <button
            className="focus-ring ui-button-primary h-10 w-full px-4"
            onClick={() => { setNewPassword(""); setConfirmPassword(""); setVerificationCode(""); goTo("password"); }}
          >
            <LogIn className="size-4" />
            Back to login
          </button>
        </Panel>
      </div>
    );
  }

  // ── Reset form ───────────────────────────────────────────────────────────────
  if (step === "reset") {
    return (
      <div className="mx-auto max-w-md pt-12">
        <Panel className="ui-elevated">
          <div className="mb-6">
            <div className="mb-3 flex items-center gap-2">
              <KeyRound className="size-6 ui-accent" />
              <h1 className="text-2xl font-semibold ui-heading">Reset Password</h1>
            </div>
            <p className="text-sm ui-muted">
              Enter your new password and confirm with a Google Authenticator code or a one-time recovery code.
            </p>
          </div>
          <form onSubmit={submitReset} className="space-y-4">
            <label className="block text-sm font-medium ui-secondary">
              New password
              <input
                className="focus-ring ui-input mt-1 rounded-md px-3 py-2"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                autoComplete="new-password"
                minLength={8}
                required
              />
            </label>
            <label className="block text-sm font-medium ui-secondary">
              Confirm new password
              <input
                className="focus-ring ui-input mt-1 rounded-md px-3 py-2"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
                required
              />
            </label>
            <label className="block text-sm font-medium ui-secondary">
              Authentication or recovery code
              <input
                ref={verificationCodeRef}
                className="focus-ring ui-input mt-1 rounded-md px-3 py-2 font-mono"
                value={verificationCode}
                onChange={(e) =>
                  setVerificationCode(e.target.value.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 19))
                }
                autoComplete="one-time-code"
                placeholder="000000 or xxxx-xxxx-xxxx-xxxx"
                maxLength={19}
              />
            </label>
            {error ? <p className="ui-error rounded-md px-3 py-2 text-sm">{error}</p> : null}
            <button
              className="focus-ring ui-button-primary h-10 w-full px-4 disabled:opacity-60"
              disabled={
                loading ||
                verificationCode.length < 6 ||
                !newPassword ||
                !confirmPassword
              }
            >
              <KeyRound className="size-4" />
              {loading ? "Resetting…" : "Reset password"}
            </button>
            <button
              type="button"
              className="w-full text-sm ui-muted hover:ui-secondary transition-colors"
              onClick={() => goTo("password")}
            >
              ← Back to login
            </button>
          </form>
        </Panel>
      </div>
    );
  }

  // ── TOTP step ────────────────────────────────────────────────────────────────
  if (step === "totp") {
    return (
      <div className="mx-auto max-w-md pt-12">
        <Panel className="ui-elevated">
          <div className="mb-6">
            <div className="mb-3 flex items-center gap-2">
              <ShieldCheck className="size-6 ui-accent" />
              <h1 className="text-2xl font-semibold ui-heading">Two-Factor Auth</h1>
            </div>
            <p className="text-sm ui-muted">
              Open Google Authenticator and enter the 6-digit code for{" "}
              <span className="font-medium ui-secondary">URL Threat Checker</span>.
            </p>
          </div>
          <form onSubmit={submitTotp} className="space-y-4">
            <label className="block text-sm font-medium ui-secondary">
              Authentication code
              <input
                ref={totpRef}
                className="focus-ring ui-input mt-1 rounded-md px-3 py-2 text-center text-2xl tracking-[0.5em]"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                maxLength={6}
              />
            </label>
            {error ? <p className="ui-error rounded-md px-3 py-2 text-sm">{error}</p> : null}
            <button
              className="focus-ring ui-button-primary h-10 w-full px-4 disabled:opacity-60"
              disabled={loading || totpCode.length !== 6}
            >
              <ShieldCheck className="size-4" />
              {loading ? "Verifying…" : "Verify"}
            </button>
            <button
              type="button"
              className="w-full text-sm ui-muted hover:ui-secondary transition-colors"
              onClick={() => { setTotpCode(""); goTo("password"); }}
            >
              ← Back to login
            </button>
          </form>
        </Panel>
      </div>
    );
  }

  // ── Password step ────────────────────────────────────────────────────────────
  return (
    <div className="mx-auto max-w-md pt-12">
      <Panel className="ui-elevated">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold ui-heading">Admin Login</h1>
          <p className="mt-2 text-sm ui-muted">Sign in to analyze URLs and review reports.</p>
        </div>
        <form onSubmit={submitPassword} className="space-y-4">
          <label className="block text-sm font-medium ui-secondary">
            Username
            <input
              className="focus-ring ui-input mt-1 rounded-md px-3 py-2"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
          </label>
          <label className="block text-sm font-medium ui-secondary">
            Password
            <input
              className="focus-ring ui-input mt-1 rounded-md px-3 py-2"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          {error ? <p className="ui-error rounded-md px-3 py-2 text-sm">{error}</p> : null}
          <button
            className="focus-ring ui-button-primary h-10 w-full px-4 disabled:opacity-60"
            disabled={loading}
          >
            <LogIn className="size-4" />
            {loading ? "Signing in…" : "Sign in"}
          </button>
          <button
            type="button"
            className="w-full text-sm ui-muted hover:ui-secondary transition-colors"
            onClick={() => goTo("reset")}
          >
            Forgot password?
          </button>
        </form>
      </Panel>
    </div>
  );
}
