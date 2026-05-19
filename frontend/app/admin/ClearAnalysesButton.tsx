"use client";

import { useState, useTransition } from "react";
import { clearAllAnalyses } from "./actions";

export default function ClearAnalysesButton() {
  const [confirmed, setConfirmed] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function handleClick() {
    if (!confirmed) {
      setConfirmed(true);
      return;
    }
    startTransition(async () => {
      try {
        const { deleted } = await clearAllAnalyses();
        setResult(`Cleared ${deleted} ${deleted === 1 ? "analysis" : "analyses"}.`);
      } catch {
        setResult("Error — check backend logs.");
      }
      setConfirmed(false);
    });
  }

  return (
    <div className="flex items-center gap-3 flex-wrap">
      <button
        onClick={handleClick}
        disabled={isPending}
        className={`text-sm px-4 py-1.5 rounded-lg font-semibold transition-all disabled:opacity-50 ${
          confirmed
            ? "bg-[var(--danger)] text-white hover:brightness-110"
            : "border border-[var(--danger)] text-[var(--danger)] hover:bg-[var(--danger)] hover:text-white"
        }`}
      >
        {isPending ? "Clearing…" : confirmed ? "Click again to confirm" : "Clear all analyses"}
      </button>
      {confirmed && !isPending && (
        <button
          onClick={() => setConfirmed(false)}
          className="text-xs text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
        >
          Cancel
        </button>
      )}
      {result && (
        <span className="text-xs text-[var(--muted)]">{result}</span>
      )}
    </div>
  );
}
