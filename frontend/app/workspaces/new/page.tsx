"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function NewWorkspacePage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/workspaces", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.detail ?? "Failed to create workspace.");
        return;
      }
      router.push(`/workspaces/${data.id}`);
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-md mx-auto w-full px-4 py-16 flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold">New workspace</h1>
        <p className="text-[var(--muted)] text-sm mt-1">
          A workspace lets your team share private analyses in a shared library.
        </p>
      </div>
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="ws-name" className="text-sm text-[var(--muted)]">Workspace name</label>
          <input
            id="ws-name"
            type="text"
            required
            maxLength={80}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. IR Team Alpha"
            className="bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--accent)] text-[var(--foreground)]"
          />
        </div>
        {error && <p className="text-[var(--danger)] text-sm">{error}</p>}
        <button
          type="submit"
          disabled={loading || !name.trim()}
          className="px-6 py-2 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg text-sm disabled:opacity-40 hover:brightness-110 transition-all"
        >
          {loading ? "Creating…" : "Create workspace"}
        </button>
      </form>
    </div>
  );
}
