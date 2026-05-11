"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { ApiKey } from "@/app/lib/api";

export default function ApiKeysClient({ initialKeys }: { initialKeys: ApiKey[] }) {
  const router = useRouter();
  const [keys, setKeys] = useState<ApiKey[]>(initialKeys);
  const [newName, setNewName] = useState("");
  const [creating, setCreating] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function createKey(e: React.FormEvent) {
    e.preventDefault();
    if (!newName.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const res = await fetch("/api/api-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newName.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.detail ?? "Failed to create key.");
        return;
      }
      setNewKey(data.key);
      setNewName("");
      setKeys((prev) => [data, ...prev]);
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setCreating(false);
    }
  }

  async function revokeKey(id: string) {
    const res = await fetch("/api/api-keys", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    if (res.ok) {
      setKeys((prev) => prev.filter((k) => k.id !== id));
      router.refresh();
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Create new key */}
      <form onSubmit={createKey} className="flex gap-3">
        <input
          type="text"
          required
          maxLength={80}
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="Key name (e.g. CI pipeline)"
          className="flex-1 bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--accent)] text-[var(--foreground)]"
        />
        <button
          type="submit"
          disabled={creating || !newName.trim()}
          className="px-5 py-2 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg text-sm disabled:opacity-40 hover:brightness-110 transition-all shrink-0"
        >
          {creating ? "Creating…" : "Create key"}
        </button>
      </form>
      {error && <p className="text-[var(--danger)] text-sm">{error}</p>}

      {/* One-time display of new key */}
      {newKey && (
        <div className="border border-[var(--success)] bg-[#0d2115] rounded-lg px-4 py-3 flex flex-col gap-2">
          <p className="text-xs text-[var(--success)] font-semibold">Copy this key now — it will not be shown again.</p>
          <code className="font-mono text-sm text-[var(--foreground)] break-all">{newKey}</code>
          <button
            onClick={() => navigator.clipboard.writeText(newKey)}
            className="text-xs text-[var(--accent)] hover:underline text-left"
          >
            Copy to clipboard
          </button>
        </div>
      )}

      {/* Key list */}
      {keys.length === 0 ? (
        <p className="text-[var(--muted)] text-sm">No API keys yet.</p>
      ) : (
        <div className="border border-[var(--border)] rounded-lg overflow-hidden">
          {keys.map((k, i) => (
            <div
              key={k.id}
              className={`px-4 py-3 flex items-center justify-between gap-4 ${i > 0 ? "border-t border-[var(--border)]" : ""}`}
            >
              <div className="flex flex-col gap-0.5">
                <span className="text-sm font-semibold">{k.name}</span>
                <span className="font-mono text-xs text-[var(--muted)]">{k.key_prefix}</span>
                <span className="text-xs text-[var(--muted)]">
                  Created {new Date(k.created_at).toLocaleDateString()}
                  {k.last_used_at && ` · Last used ${new Date(k.last_used_at).toLocaleDateString()}`}
                </span>
              </div>
              <button
                onClick={() => revokeKey(k.id)}
                className="text-xs text-[var(--danger)] hover:underline shrink-0"
              >
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
