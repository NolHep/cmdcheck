"use client";

import { useState } from "react";
import Link from "next/link";
import { apiBase } from "@/app/lib/api";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch(`${apiBase()}/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      if (!res.ok) {
        setError("Something went wrong. Please try again.");
        return;
      }
      setSubmitted(true);
    } catch {
      setError("Network error. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }

  if (submitted) {
    return (
      <div className="max-w-sm mx-auto w-full px-4 py-16">
        <h1 className="text-2xl font-bold mb-2">Check your email</h1>
        <p className="text-[var(--muted)] text-sm mb-6">
          If an account exists for <span className="text-[var(--foreground)]">{email}</span>, we sent a password reset link. Check your inbox and spam folder.
        </p>
        <p className="text-[var(--muted)] text-sm">
          The link expires in 1 hour.{" "}
          <button
            onClick={() => { setSubmitted(false); setEmail(""); }}
            className="text-[var(--accent)] hover:underline"
          >
            Send another
          </button>
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-sm mx-auto w-full px-4 py-16">
      <h1 className="text-2xl font-bold mb-1">Reset password</h1>
      <p className="text-[var(--muted)] text-sm mb-8">
        Enter your email and we'll send a reset link.{" "}
        <Link href="/login" className="text-[var(--accent)] hover:underline">
          Back to sign in
        </Link>
      </p>

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="email" className="text-sm text-[var(--muted)]">Email</label>
          <input
            id="email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
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
          {loading ? "Sending…" : "Send reset link"}
        </button>
      </form>
    </div>
  );
}
