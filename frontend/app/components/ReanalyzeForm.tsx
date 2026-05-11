"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { postAnalyze } from "@/app/lib/api";

export default function ReanalyzeForm({ command, slug }: { command: string; slug: string }) {
  const router = useRouter();
  const [parent, setParent] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!parent.trim()) return;
    setError(null);
    startTransition(async () => {
      try {
        const result = await postAnalyze(command, parent.trim());
        // Same slug — just refresh so parent_verdict appears
        if (result.slug === slug) {
          router.refresh();
        } else {
          router.push(`/c/${result.slug}`);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed");
      }
    });
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-2">
      <p className="text-xs text-[var(--muted)]">Add parent process context</p>
      <div className="flex gap-2">
        <input
          value={parent}
          onChange={(e) => setParent(e.target.value)}
          placeholder="e.g. winword.exe"
          spellCheck={false}
          className="flex-1 min-w-0 font-mono text-sm bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)]"
        />
        <button
          type="submit"
          disabled={isPending || !parent.trim()}
          className="px-3 py-1.5 bg-[var(--accent)] text-[#0d1117] text-sm font-semibold rounded-lg disabled:opacity-40 disabled:cursor-not-allowed hover:brightness-110 transition-all"
        >
          {isPending ? "…" : "Analyze"}
        </button>
      </div>
      {error && <p className="text-xs text-[var(--danger)]">{error}</p>}
    </form>
  );
}
