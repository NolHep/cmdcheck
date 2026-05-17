"use client";

import { useState, Suspense } from "react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { apiBase } from "@/app/lib/api";

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const rawNext = params.get("next") ?? "/";
  // Reject absolute URLs and protocol-relative paths to prevent open-redirect.
  const next = /^\/(?!\/)/.test(rawNext) ? rawNext : "/";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [needsVerification, setNeedsVerification] = useState(false);
  const [resendStatus, setResendStatus] = useState<"idle" | "sending" | "sent" | "error">("idle");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNeedsVerification(false);
    setLoading(true);
    const result = await signIn("credentials", {
      email,
      password,
      redirect: false,
    });
    setLoading(false);
    if (result?.error) {
      // Ask the backend directly to distinguish "wrong password" from "unverified email"
      try {
        const check = await fetch(`${apiBase()}/auth/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        if (!check.ok) {
          const body = await check.json().catch(() => ({}));
          if (body?.detail?.code === "email_not_verified") {
            setNeedsVerification(true);
            setError("Please verify your email before signing in. Check your inbox.");
            return;
          }
        }
      } catch { /* network error — fall through to generic message */ }
      setError("Invalid email or password.");
    } else {
      router.push(next);
      router.refresh();
    }
  }

  async function handleResend() {
    setResendStatus("sending");
    try {
      const res = await fetch(`${apiBase()}/auth/resend-verification`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      setResendStatus(res.ok ? "sent" : "error");
    } catch {
      setResendStatus("error");
    }
  }

  return (
    <div className="max-w-sm mx-auto w-full px-4 py-16">
      <h1 className="text-2xl font-bold mb-1">Sign in</h1>
      <p className="text-[var(--muted)] text-sm mb-8">
        Don&apos;t have an account?{" "}
        <Link href="/register" className="text-[var(--accent)] hover:underline">
          Register
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

        <div className="flex flex-col gap-1.5">
          <label htmlFor="password" className="text-sm text-[var(--muted)]">Password</label>
          <input
            id="password"
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            className="bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--accent)] text-[var(--foreground)]"
          />
        </div>

        {error && (
          <div className="flex flex-col gap-2">
            <p className="text-[var(--danger)] text-sm" role="alert">{error}</p>
            {needsVerification && resendStatus === "idle" && (
              <button
                type="button"
                onClick={handleResend}
                className="text-[var(--accent)] text-sm hover:underline text-left"
              >
                Resend verification email
              </button>
            )}
            {resendStatus === "sending" && (
              <p className="text-[var(--muted)] text-sm">Sending…</p>
            )}
            {resendStatus === "sent" && (
              <p className="text-[var(--success)] text-sm">Verification email sent. Check your inbox.</p>
            )}
            {resendStatus === "error" && (
              <p className="text-[var(--danger)] text-sm">Failed to resend. Try again shortly.</p>
            )}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="px-6 py-2 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg disabled:opacity-40 hover:brightness-110 transition-all"
        >
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
