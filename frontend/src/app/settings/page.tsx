"use client";

import { FormEvent, useState } from "react";
import { KeyRound, CheckCircle } from "lucide-react";
import { Panel } from "@/components/panel";
import { changePassword } from "@/lib/api";

export default function SettingsPage() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(false);
    if (newPassword !== confirmPassword) {
      setError("New passwords do not match.");
      return;
    }
    if (newPassword === currentPassword) {
      setError("New password must differ from the current one.");
      return;
    }
    setLoading(true);
    try {
      await changePassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setSuccess(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Password change failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-xl">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold ui-heading">Settings</h1>
        <p className="mt-1 text-sm ui-muted">Manage your administrator credentials.</p>
      </div>

      <Panel className="ui-elevated">
        <div className="mb-5 flex items-center gap-2">
          <KeyRound className="size-5 ui-accent" />
          <h2 className="text-lg font-medium ui-heading">Change password</h2>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <label className="block text-sm font-medium ui-secondary">
            Current password
            <input
              className="focus-ring ui-input mt-1 rounded-md px-3 py-2"
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
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

          {error ? <p className="ui-error rounded-md px-3 py-2 text-sm">{error}</p> : null}
          {success ? (
            <p className="ui-success flex items-center gap-2 rounded-md px-3 py-2 text-sm">
              <CheckCircle className="size-4" />
              Password updated. Other devices have been signed out.
            </p>
          ) : null}

          <button
            className="focus-ring ui-button-primary h-10 w-full px-4 disabled:opacity-60"
            disabled={loading || !currentPassword || !newPassword || !confirmPassword}
          >
            <KeyRound className="size-4" />
            {loading ? "Updating…" : "Update password"}
          </button>
        </form>
      </Panel>
    </div>
  );
}
