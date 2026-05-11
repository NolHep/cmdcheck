"use client";

import { useState, useEffect, useRef, useTransition } from "react";
import { useRouter } from "next/navigation";
import { postAnalyze } from "@/app/lib/api";

interface Workspace { id: string; name: string }

export default function CommandForm({
  defaultCommand = "",
  loggedIn = false,
  workspaces = [],
}: {
  defaultCommand?: string;
  loggedIn?: boolean;
  workspaces?: Workspace[];
}) {
  const router = useRouter();
  const [command, setCommand] = useState(defaultCommand);
  const [isPrivate, setIsPrivate] = useState(false);
  const [skipRedaction, setSkipRedaction] = useState(false);
  const [selectedWorkspace, setSelectedWorkspace] = useState<string>("");
  const formRef = useRef<HTMLFormElement>(null);

  // Sync when a new example is selected without remounting the whole form
  useEffect(() => {
    if (defaultCommand) {
      setCommand(defaultCommand);
      formRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [defaultCommand]);
  const [parentProcess, setParentProcess] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = command.trim();
    if (!trimmed) return;
    setError(null);

    startTransition(async () => {
      try {
        const result = await postAnalyze(trimmed, parentProcess.trim() || undefined, {
          isPrivate: loggedIn && (isPrivate || !!selectedWorkspace),
          skipRedaction: loggedIn && skipRedaction,
          workspaceId: selectedWorkspace || undefined,
        });
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
      <div className="flex items-center gap-3">
        <label htmlFor="parent-process" className="text-[var(--muted)] text-xs whitespace-nowrap shrink-0">
          Parent process
        </label>
        <input
          id="parent-process"
          type="text"
          value={parentProcess}
          onChange={(e) => setParentProcess(e.target.value)}
          placeholder="e.g. winword.exe"
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          className="flex-1 font-mono text-sm bg-[var(--surface)] text-[var(--foreground)] border border-[var(--border)] rounded-lg px-3 py-1.5 focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)]"
        />
        <span className="text-[var(--muted)] text-xs italic shrink-0">optional</span>
      </div>
      {loggedIn && (
        <div className="flex flex-col gap-2">
          {workspaces.length > 0 && (
            <div className="flex items-center gap-2">
              <label htmlFor="workspace-select" className="text-xs text-[var(--muted)] whitespace-nowrap shrink-0">
                Save to workspace
              </label>
              <select
                id="workspace-select"
                value={selectedWorkspace}
                onChange={(e) => setSelectedWorkspace(e.target.value)}
                className="flex-1 bg-[var(--surface)] border border-[var(--border)] rounded px-2 py-1 text-xs text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)]"
              >
                <option value="">None (personal)</option>
                {workspaces.map((ws) => (
                  <option key={ws.id} value={ws.id}>{ws.name}</option>
                ))}
              </select>
            </div>
          )}
          <label className="flex items-center gap-2 cursor-pointer w-fit">
            <input
              type="checkbox"
              checked={isPrivate || !!selectedWorkspace}
              onChange={(e) => { setIsPrivate(e.target.checked); if (!e.target.checked) setSelectedWorkspace(""); }}
              disabled={!!selectedWorkspace}
              className="w-4 h-4 accent-[var(--accent)]"
            />
            <span className="text-xs text-[var(--muted)]">
              Submit privately — not indexed in public corpus
            </span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer w-fit">
            <input
              type="checkbox"
              checked={skipRedaction}
              onChange={(e) => setSkipRedaction(e.target.checked)}
              className="w-4 h-4 accent-[var(--accent)]"
            />
            <span className="text-xs text-[var(--muted)]">
              Don&apos;t redact sensitive data — store exact command as submitted
            </span>
          </label>
        </div>
      )}
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
