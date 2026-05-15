"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { LogIn } from "lucide-react";
import { Panel } from "@/components/panel";
import { login } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await login(username, password);
      router.push("/dashboard");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Login failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-md pt-12">
      <Panel className="ui-elevated">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold ui-heading">Admin Login</h1>
          <p className="mt-2 text-sm ui-muted">Sign in to analyze URLs and review reports.</p>
        </div>
        <form onSubmit={submit} className="space-y-4">
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
            {loading ? "Signing in" : "Sign in"}
          </button>
        </form>
      </Panel>
    </div>
  );
}
