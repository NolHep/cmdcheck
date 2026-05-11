"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function AcceptInviteButton({ token, workspaceId }: { token: string; workspaceId: string }) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function accept() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/workspaces/accept", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (res.ok) {
        router.push(`/workspaces/${workspaceId}`);
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data?.detail ?? "Failed to accept invite.");
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col items-center gap-2">
      <button
        onClick={accept}
        disabled={loading}
        className="px-8 py-2.5 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg text-sm disabled:opacity-40 hover:brightness-110 transition-all"
      >
        {loading ? "Joining…" : "Accept invite"}
      </button>
      {error && <p className="text-[var(--danger)] text-xs">{error}</p>}
    </div>
  );
}
