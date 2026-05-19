"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { postAnalyze } from "@/app/lib/api";

export default function RerunButton({ command, slug }: { command: string; slug: string }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function handleClick() {
    setError(null);
    startTransition(async () => {
      try {
        await postAnalyze(command, undefined, { force: true, loggedIn: true });
        router.refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to re-run analysis");
      }
    });
  }

  return (
    <div className="flex flex-col gap-1">
      <button
        onClick={handleClick}
        disabled={isPending}
        className="text-xs text-[var(--muted)] hover:text-[var(--accent)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      >
        {isPending ? "Re-running…" : "Re-run analysis"}
      </button>
      {error && <p className="text-xs text-[var(--danger)]">{error}</p>}
    </div>
  );
}
