"use client";

import { useState, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import { apiBase } from "@/app/lib/api";

function ResetPasswordForm() {
  const params = useSearchParams();
  const router = useRouter();
  const token = params.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  if (!token) {
    return (
      <div className="max-w-sm mx-auto w-full px-4 py-16">
        <h1 className="text-2xl font-bold mb-2">Invalid link</h1>
        <p className="text-[var(--muted)] text-sm mb-6">
          This reset link is missing a token.{" "}
          <Link href="/forgot-password" className="text-[var(--accent)] hover:underline">
            Request a new one
          </Link>
        </p>
      </div>
    );
  }

  if (done) {
    return (
      <div className="max-w-sm mx-auto w-full px-4 py-16">
        <h1 className="text-2xl font-bold mb-2">Password updated</h1>
        <p className="text-[var(--muted)] text-sm mb-6">
          Your password has been reset. You can now sign in with your new password.
        </p>
        <Link
          href="/login"
          className="inline-block px-6 py-2 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg hover:brightness-110 transition-all text-sm"
        >
          Sign in
        </Link>
      </div>
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${apiBase()}/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        if (body?.detail?.code === "invalid_token") {
          setError("This reset link has expired or already been used. Request a new one.");
        } else {
          setError("Something went wrong. Please try again.");
        }
        return;
      }
      setDone(true);
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-sm mx-auto w-full px-4 py-16">
      <h1 className="text-2xl font-bold mb-1">Set new password</h1>
      <p className="text-[var(--muted)] text-sm mb-8">
        Choose a new password for your account.
      </p>

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="password" className="text-sm text-[var(--muted)]">New password</label>
          <input
            id="password"
            type="password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            className="bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--accent)] text-[var(--foreground)]"
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="confirm" className="text-sm text-[var(--muted)]">Confirm password</label>
          <input
            id="confirm"
            type="password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            className="bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--accent)] text-[var(--foreground)]"
          />
        </div>

        {error && (
          <p className="text-[var(--danger)] text-sm" role="alert">{error}</p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="px-6 py-2 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg disabled:opacity-40 hover:brightness-110 transition-all"
        >
          {loading ? "Updating…" : "Set new password"}
        </button>
      </form>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPasswordForm />
    </Suspense>
  );
}
