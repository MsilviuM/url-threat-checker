"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { LogIn, ShieldCheck } from "lucide-react";
import { Panel } from "@/components/panel";
import { login, verify2fa } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [step, setStep] = useState<"password" | "totp">("password");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const codeRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (step === "totp") codeRef.current?.focus();
  }, [step]);

  async function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await login(username, password);
      if (result.requires_2fa) {
        setStep("totp");
      } else {
        router.push("/dashboard");
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Login failed.");
    } finally {
      setLoading(false);
    }
  }

  async function submitTotp(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await verify2fa(code);
      router.push("/dashboard");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Invalid code.");
      setCode("");
      codeRef.current?.focus();
    } finally {
      setLoading(false);
    }
  }

  function handleCodeChange(value: string) {
    const digits = value.replace(/\D/g, "").slice(0, 6);
    setCode(digits);
  }

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
                ref={codeRef}
                className="focus-ring ui-input mt-1 rounded-md px-3 py-2 text-center text-2xl tracking-[0.5em]"
                value={code}
                onChange={(e) => handleCodeChange(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                maxLength={6}
              />
            </label>
            {error ? <p className="ui-error rounded-md px-3 py-2 text-sm">{error}</p> : null}
            <button
              className="focus-ring ui-button-primary h-10 w-full px-4 disabled:opacity-60"
              disabled={loading || code.length !== 6}
            >
              <ShieldCheck className="size-4" />
              {loading ? "Verifying…" : "Verify"}
            </button>
            <button
              type="button"
              className="w-full text-sm ui-muted hover:ui-secondary transition-colors"
              onClick={() => { setStep("password"); setError(null); setCode(""); }}
            >
              ← Back to login
            </button>
          </form>
        </Panel>
      </div>
    );
  }

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
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
            />
          </label>
          <label className="block text-sm font-medium ui-secondary">
            Password
            <input
              className="focus-ring ui-input mt-1 rounded-md px-3 py-2"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
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
        </form>
      </Panel>
    </div>
  );
}
