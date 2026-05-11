"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

interface Props {
  tier: "individual" | "teams";
  featured?: boolean;
  label?: string;
  loggedIn: boolean;
}

export default function CheckoutButton({ tier, featured = false, label = "Subscribe", loggedIn }: Props) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleClick() {
    setError(null);

    if (!loggedIn) {
      router.push("/login?next=/pricing");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/billing/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tier }),
      });

      const data = await res.json();

      if (!res.ok) {
        // 401 means session expired — send to login
        if (res.status === 401) {
          router.push("/login?next=/pricing");
          return;
        }
        setError(data?.detail ?? "Something went wrong. Please try again.");
        return;
      }

      window.location.href = data.url;
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-1.5">
      <button
        onClick={handleClick}
        disabled={loading}
        className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed ${
          featured
            ? "bg-[var(--accent)] text-[#0d1117] hover:brightness-110"
            : "border border-[var(--border)] text-[var(--foreground)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
        }`}
      >
        {loading ? "Redirecting to Stripe…" : loggedIn ? label : "Sign in to subscribe"}
      </button>
      {error && (
        <p className="text-[var(--danger)] text-xs text-center">{error}</p>
      )}
    </div>
  );
}
