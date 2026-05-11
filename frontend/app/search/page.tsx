"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { searchAnalyses } from "@/app/lib/api";
import type { RecentItem } from "@/app/lib/api";

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function VerdictDot({ item }: { item: RecentItem }) {
  const color =
    item.threat_labels.length > 0
      ? "bg-[var(--danger)]"
      : item.has_lolbas || item.has_encoding
      ? "bg-yellow-500"
      : "bg-[var(--muted)]";
  return <span className={`w-2 h-2 rounded-full shrink-0 mt-1.5 ${color}`} />;
}

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<RecentItem[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (debounce.current) clearTimeout(debounce.current);
    const q = query.trim();
    if (q.length < 2) {
      setResults(null);
      setError(null);
      return;
    }
    debounce.current = setTimeout(async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await searchAnalyses(q);
        setResults(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Search failed");
        setResults(null);
      } finally {
        setLoading(false);
      }
    }, 350);
    return () => {
      if (debounce.current) clearTimeout(debounce.current);
    };
  }, [query]);

  return (
    <div className="max-w-3xl mx-auto w-full px-4 py-8 flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-bold mb-1">Search corpus</h1>
        <p className="text-[var(--muted)] text-sm">
          Search across all public analyses by command content.
        </p>
      </div>

      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="powershell -enc, certutil, mshta…"
        autoFocus
        className="w-full font-mono text-sm bg-[var(--surface)] text-[var(--foreground)] border border-[var(--border)] rounded-lg px-4 py-3 focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)]"
      />

      {query.trim().length === 1 && (
        <p className="text-[var(--muted)] text-xs">Type at least 2 characters to search.</p>
      )}

      {loading && (
        <p className="text-[var(--muted)] text-sm">Searching…</p>
      )}

      {error && (
        <p className="text-[var(--danger)] text-sm" role="alert">{error}</p>
      )}

      {results !== null && !loading && (
        results.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-[var(--muted)] text-sm">No results for &ldquo;{query.trim()}&rdquo;</p>
            <Link href="/" className="text-[var(--accent)] text-sm hover:underline mt-2 inline-block">
              Analyze a new command →
            </Link>
          </div>
        ) : (
          <div className="flex flex-col gap-1">
            <p className="text-[var(--muted)] text-xs mb-1">{results.length} result{results.length !== 1 ? "s" : ""}</p>
            {results.map((item) => (
              <Link
                key={item.slug}
                href={`/c/${item.slug}`}
                className="flex items-start gap-3 border border-[var(--border)] rounded-lg px-4 py-3 hover:border-[var(--accent)] hover:bg-[var(--surface)] transition-colors group"
              >
                <VerdictDot item={item} />
                <div className="flex-1 min-w-0">
                  <p className="font-mono text-xs text-[var(--foreground)] truncate group-hover:text-[var(--accent)] transition-colors">
                    {item.command}
                  </p>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    {item.threat_labels.map((lbl) => (
                      <span key={lbl} className="text-xs bg-[#3d1a1a] text-[var(--danger)] border border-[var(--danger)] border-opacity-30 px-1.5 py-0.5 rounded">
                        {lbl}
                      </span>
                    ))}
                    {item.has_lolbas && (
                      <span className="text-xs text-[var(--muted)] border border-[var(--border)] px-1.5 py-0.5 rounded">LOLBAS</span>
                    )}
                    {item.has_encoding && (
                      <span className="text-xs text-[var(--muted)] border border-[var(--border)] px-1.5 py-0.5 rounded">encoded</span>
                    )}
                    <span className="text-xs text-[var(--muted)] ml-auto shrink-0">{timeAgo(item.created_at)}</span>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        )
      )}
    </div>
  );
}
