"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { postAnalyze } from "@/app/lib/api";

export default function CommandForm() {
  const router = useRouter();
  const [command, setCommand] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = command.trim();
    if (!trimmed) return;
    setError(null);

    startTransition(async () => {
      try {
        const result = await postAnalyze(trimmed);
        router.push(`/c/${result.slug}`);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Analysis failed. Is the backend running?");
      }
    });
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4 w-full">
      <label htmlFor="command-input" className="sr-only">
        Paste command
      </label>
      <textarea
        id="command-input"
        data-testid="command-input"
        value={command}
        onChange={(e) => setCommand(e.target.value)}
        placeholder={`Paste a suspicious command line here…\n\npowershell -enc JAB…\nmshta "javascript:…"\ncertutil -decode payload.b64 out.exe`}
        rows={10}
        spellCheck={false}
        autoCorrect="off"
        autoCapitalize="off"
        className="w-full font-mono text-sm bg-[var(--surface)] text-[var(--foreground)] border border-[var(--border)] rounded-lg px-4 py-3 resize-y focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)]"
      />
      {error && (
        <p className="text-[var(--danger)] text-sm" role="alert">
          {error}
        </p>
      )}
      <div className="flex items-center gap-4">
        <button
          type="submit"
          disabled={isPending || !command.trim()}
          className="px-6 py-2 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg disabled:opacity-40 disabled:cursor-not-allowed hover:brightness-110 transition-all"
        >
          {isPending ? "Analyzing…" : "Analyze"}
        </button>
        <span className="text-[var(--muted)] text-xs">
          Every analysis gets a shareable permalink
        </span>
      </div>
    </form>
  );
}
