"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function WorkspaceActions({
  workspaceId,
  isOwner,
}: {
  workspaceId: string;
  isOwner: boolean;
}) {
  const router = useRouter();
  const [inviteEmail, setInviteEmail] = useState("");
  const [showInvite, setShowInvite] = useState(false);
  const [inviteResult, setInviteResult] = useState<string | null>(null);
  const [inviteLoading, setInviteLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function sendInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!inviteEmail.trim()) return;
    setInviteLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/workspaces/${workspaceId}/invite`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ invite_email: inviteEmail.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.detail ?? "Failed to send invite.");
        return;
      }
      const link = `${window.location.origin}/workspaces/invite/${data.token}`;
      setInviteResult(link);
      setInviteEmail("");
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setInviteLoading(false);
    }
  }

  async function copyLink() {
    if (inviteResult) await navigator.clipboard.writeText(inviteResult);
  }

  return (
    <div className="flex flex-col gap-3 items-end shrink-0">
      {isOwner && (
        <button
          onClick={() => { setShowInvite(!showInvite); setInviteResult(null); setError(null); }}
          className="px-4 py-2 border border-[var(--border)] text-[var(--foreground)] rounded-lg text-sm hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors"
        >
          Invite member
        </button>
      )}

      {showInvite && isOwner && (
        <div className="border border-[var(--border)] bg-[var(--surface)] rounded-lg p-4 flex flex-col gap-3 w-72">
          {inviteResult ? (
            <>
              <p className="text-xs text-[var(--muted)]">Share this invite link (expires in 7 days):</p>
              <code className="text-xs font-mono bg-[var(--border)] px-2 py-1.5 rounded break-all">{inviteResult}</code>
              <button onClick={copyLink} className="text-xs text-[var(--accent)] hover:underline text-left">
                Copy link
              </button>
            </>
          ) : (
            <form onSubmit={sendInvite} className="flex flex-col gap-2">
              <input
                type="email"
                required
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                placeholder="colleague@example.com"
                className="bg-transparent border border-[var(--border)] rounded px-3 py-1.5 text-sm focus:outline-none focus:border-[var(--accent)] text-[var(--foreground)]"
              />
              {error && <p className="text-[var(--danger)] text-xs">{error}</p>}
              <button
                type="submit"
                disabled={inviteLoading}
                className="px-4 py-1.5 bg-[var(--accent)] text-[#0d1117] font-semibold rounded text-sm disabled:opacity-40"
              >
                {inviteLoading ? "Sending…" : "Generate invite link"}
              </button>
            </form>
          )}
        </div>
      )}
    </div>
  );
}
