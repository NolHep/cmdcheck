"use client";

import { useState } from "react";

export default function ManageSubscriptionButton({ loggedIn }: { loggedIn: boolean }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!loggedIn) return null;

  async function handleClick() {
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/billing/portal", { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.detail ?? "Could not open billing portal.");
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
    <div className="flex flex-col items-start gap-1">
      <button
        onClick={handleClick}
        disabled={loading}
        className="text-sm text-[var(--accent)] hover:underline disabled:opacity-40"
      >
        {loading ? "Opening portal…" : "Manage subscription →"}
      </button>
      {error && <p className="text-[var(--danger)] text-xs">{error}</p>}
    </div>
  );
}
