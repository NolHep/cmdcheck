"use client";

import { useState, useTransition, useEffect, useRef } from "react";
import Link from "next/link";
import { createGroup, deleteGroup, addMember, removeMember } from "./actions";
import { searchAnalyses, getRecentAnalyses } from "@/app/lib/api";
import type { RecentItem } from "@/app/lib/api";

type Member = {
  slug: string;
  notes: string | null;
  added_at: string;
  command: string | null;
};

type Group = {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  members: Member[];
};

function extractSlug(input: string): string {
  const trimmed = input.trim();
  // Accept full URLs like http://localhost:3000/c/WXRDPQLTS7XD
  const match = trimmed.match(/\/c\/([A-Z2-7]{12})$/i);
  if (match) return match[1].toUpperCase();
  // Accept bare slug
  if (/^[A-Z2-7]{12}$/i.test(trimmed)) return trimmed.toUpperCase();
  return "";
}

function SlugFinder({ onSelect }: { onSelect: (slug: string) => void }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<RecentItem[]>([]);
  const [loading, setLoading] = useState(false);
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (debounce.current) clearTimeout(debounce.current);
    const q = query.trim();
    if (q.length === 0) {
      setLoading(true);
      getRecentAnalyses().then((r) => { setResults(r.slice(0, 8)); setLoading(false); }).catch(() => setLoading(false));
      return;
    }
    if (q.length < 2) { setResults([]); return; }
    debounce.current = setTimeout(async () => {
      setLoading(true);
      try { setResults((await searchAnalyses(q)).slice(0, 8)); }
      catch { setResults([]); }
      finally { setLoading(false); }
    }, 300);
    return () => { if (debounce.current) clearTimeout(debounce.current); };
  }, [query]);

  return (
    <div className="border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="px-3 py-2 bg-[var(--surface)] border-b border-[var(--border)]">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search analyses to link…"
          className="w-full text-xs bg-transparent text-[var(--foreground)] focus:outline-none placeholder:text-[var(--muted)]"
        />
      </div>
      <div className="max-h-48 overflow-y-auto">
        {loading && <p className="px-3 py-2 text-xs text-[var(--muted)]">Loading…</p>}
        {!loading && results.length === 0 && query.length >= 2 && (
          <p className="px-3 py-2 text-xs text-[var(--muted)]">No results</p>
        )}
        {results.map((r) => (
          <button
            key={r.slug}
            type="button"
            onClick={() => { onSelect(r.slug); setQuery(""); }}
            className="w-full text-left px-3 py-2 hover:bg-[var(--surface)] border-b border-[var(--border)] last:border-0 transition-colors"
          >
            <span className="font-mono text-xs text-[var(--accent)]">{r.slug}</span>
            <span className="text-xs text-[var(--muted)] ml-2 truncate">{r.command.slice(0, 60)}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function GroupCard({ group, onUpdate }: { group: Group; onUpdate: (g: Group | null) => void }) {
  const [addInput, setAddInput] = useState("");
  const [notesInput, setNotesInput] = useState("");
  const [addError, setAddError] = useState<string | null>(null);
  const [showFinder, setShowFinder] = useState(false);
  const [isPending, startTransition] = useTransition();

  function handleAdd() {
    const slug = extractSlug(addInput);
    if (!slug) {
      setAddError("Enter a valid 12-character slug or a /c/… URL");
      return;
    }
    setAddError(null);
    startTransition(async () => {
      try {
        const member = await addMember(group.id, slug, notesInput);
        onUpdate({ ...group, members: [...group.members, member] });
        setAddInput("");
        setNotesInput("");
      } catch (e) {
        setAddError(e instanceof Error ? e.message : "Failed to add");
      }
    });
  }

  function handleRemove(slug: string) {
    startTransition(async () => {
      await removeMember(group.id, slug);
      onUpdate({ ...group, members: group.members.filter((m) => m.slug !== slug) });
    });
  }

  function handleDelete() {
    if (!confirm(`Delete group "${group.name}" and all its links?`)) return;
    startTransition(async () => {
      await deleteGroup(group.id);
      onUpdate(null);
    });
  }

  return (
    <div className="border border-[var(--border)] rounded-lg overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 bg-[var(--surface)] border-b border-[var(--border)] flex items-start justify-between gap-4">
        <div>
          <h3 className="font-semibold text-[var(--foreground)]">{group.name}</h3>
          {group.description && (
            <p className="text-xs text-[var(--muted)] mt-0.5">{group.description}</p>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs text-[var(--muted)]">{group.members.length} linked</span>
          <button
            onClick={handleDelete}
            disabled={isPending}
            className="text-xs text-[var(--danger)] hover:underline disabled:opacity-40"
          >
            Delete group
          </button>
        </div>
      </div>

      {/* Members */}
      <div className="px-4 py-3 flex flex-col gap-2">
        {group.members.length === 0 && (
          <p className="text-xs text-[var(--muted)] italic">No analyses linked yet.</p>
        )}
        {group.members.map((m) => (
          <div
            key={m.slug}
            className="flex items-start gap-3 p-2 rounded border border-[var(--border)] bg-[var(--surface)] text-sm"
          >
            <Link
              href={`/c/${m.slug}`}
              className="font-mono text-[var(--accent)] hover:underline shrink-0 text-xs pt-0.5"
              target="_blank"
            >
              {m.slug}
            </Link>
            <div className="flex-1 min-w-0">
              {m.command && (
                <p className="text-xs text-[var(--foreground)] truncate" title={m.command}>
                  {m.command}
                </p>
              )}
              {!m.command && (
                <p className="text-xs text-[var(--muted)] italic">Analysis deleted or not found</p>
              )}
              {m.notes && (
                <p className="text-xs text-[var(--accent)] mt-0.5">{m.notes}</p>
              )}
            </div>
            <button
              onClick={() => handleRemove(m.slug)}
              disabled={isPending}
              className="text-xs text-[var(--muted)] hover:text-[var(--danger)] shrink-0 disabled:opacity-40"
              title="Remove from group"
            >
              ✕
            </button>
          </div>
        ))}

        {/* Add member */}
        <div className="mt-2 flex flex-col gap-1.5">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs text-[var(--muted)]">Link analysis</span>
            <button
              type="button"
              onClick={() => setShowFinder((v) => !v)}
              className="text-xs text-[var(--accent)] hover:underline"
            >
              {showFinder ? "hide browser" : "browse recent"}
            </button>
          </div>
          {showFinder && (
            <SlugFinder onSelect={(slug) => { setAddInput(slug); setShowFinder(false); }} />
          )}
          <div className="flex gap-2">
            <input
              value={addInput}
              onChange={(e) => { setAddInput(e.target.value); setAddError(null); }}
              onKeyDown={(e) => e.key === "Enter" && handleAdd()}
              placeholder="Slug or /c/… URL"
              spellCheck={false}
              className="flex-1 min-w-0 font-mono text-xs bg-[var(--surface)] border border-[var(--border)] rounded px-2 py-1.5 text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)]"
            />
            <input
              value={notesInput}
              onChange={(e) => setNotesInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAdd()}
              placeholder="Notes (optional)"
              className="w-40 text-xs bg-[var(--surface)] border border-[var(--border)] rounded px-2 py-1.5 text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)]"
            />
            <button
              onClick={handleAdd}
              disabled={isPending || !addInput.trim()}
              className="text-xs px-3 py-1.5 bg-[var(--accent)] text-[#0d1117] font-semibold rounded hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {isPending ? "…" : "Link"}
            </button>
          </div>
          {addError && <p className="text-xs text-[var(--danger)]">{addError}</p>}
        </div>
      </div>
    </div>
  );
}

export default function ThreatMapClient({ initialGroups }: { initialGroups: Group[] }) {
  const [groups, setGroups] = useState<Group[]>(initialGroups);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function handleCreate() {
    if (!newName.trim()) return;
    setCreateError(null);
    startTransition(async () => {
      try {
        const group = await createGroup(newName.trim(), newDesc.trim());
        setGroups((prev) => [group, ...prev]);
        setNewName("");
        setNewDesc("");
      } catch {
        setCreateError("Failed to create group");
      }
    });
  }

  function handleGroupUpdate(id: string, updated: Group | null) {
    if (updated === null) {
      setGroups((prev) => prev.filter((g) => g.id !== id));
    } else {
      setGroups((prev) => prev.map((g) => (g.id === id ? updated : g)));
    }
  }

  return (
    <div className="flex flex-col gap-8">
      {/* Create group */}
      <section>
        <h2 className="section-label mb-3">New threat actor / campaign</h2>
        <div className="border border-[var(--border)] rounded-lg p-4 bg-[var(--surface)] flex flex-col gap-3">
          <div className="flex gap-3 flex-wrap">
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              placeholder="Group name (e.g. Lazarus / TA577 / ClickFix campaign)"
              className="flex-1 min-w-0 text-sm bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)]"
            />
            <input
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              placeholder="Description (optional)"
              className="w-64 text-sm bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)]"
            />
            <button
              onClick={handleCreate}
              disabled={isPending || !newName.trim()}
              className="px-4 py-2 bg-[var(--accent)] text-[#0d1117] text-sm font-semibold rounded-lg hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {isPending ? "Creating…" : "Create group"}
            </button>
          </div>
          {createError && <p className="text-xs text-[var(--danger)]">{createError}</p>}
        </div>
      </section>

      {/* Groups */}
      <section>
        <h2 className="section-label mb-3">
          {groups.length === 0 ? "No groups yet" : `${groups.length} group${groups.length !== 1 ? "s" : ""}`}
        </h2>
        {groups.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">
            Create a group above, then link analysis slugs into it to build out your threat actor map.
          </p>
        ) : (
          <div className="flex flex-col gap-4">
            {groups.map((g) => (
              <GroupCard
                key={g.id}
                group={g}
                onUpdate={(updated) => handleGroupUpdate(g.id, updated)}
              />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
