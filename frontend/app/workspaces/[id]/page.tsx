import type { Metadata } from "next";
import Link from "next/link";
import { auth } from "@/auth";
import { redirect, notFound } from "next/navigation";
import WorkspaceActions from "./WorkspaceActions";

export const metadata: Metadata = { title: "Workspace — cmdcheck" };

const backend = process.env.BACKEND_URL ?? "http://localhost:8000";

async function getWorkspace(id: string, email: string) {
  try {
    const res = await fetch(
      `${backend}/workspaces/${id}?email=${encodeURIComponent(email)}`,
      { cache: "no-store" },
    );
    if (res.status === 404) return null;
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export default async function WorkspacePage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const session = await auth();
  if (!session?.user) redirect(`/login?next=/workspaces/${id}`);

  const ws = await getWorkspace(id, session.user.email!);
  if (!ws) notFound();

  return (
    <div className="max-w-3xl mx-auto w-full px-4 py-10 flex flex-col gap-8">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <p className="text-[var(--muted)] text-xs mb-1">
            <Link href="/workspaces" className="hover:text-[var(--foreground)]">Workspaces</Link>
            {" / "}
          </p>
          <h1 className="text-2xl font-bold">{ws.name}</h1>
          <p className="text-[var(--muted)] text-xs mt-1">Your role: {ws.your_role}</p>
        </div>
        <WorkspaceActions workspaceId={id} isOwner={ws.your_role === "owner"} />
      </div>

      {/* Members */}
      <section>
        <h2 className="section-label">Members</h2>
        <div className="border border-[var(--border)] rounded-lg overflow-hidden">
          {ws.members.map((m: { id: string; email: string; role: string; joined_at: string }, i: number) => (
            <div
              key={m.id}
              className={`px-4 py-3 flex items-center justify-between gap-4 ${i > 0 ? "border-t border-[var(--border)]" : ""}`}
            >
              <span className="text-sm font-mono text-[var(--foreground)]">{m.email}</span>
              <span className="text-xs text-[var(--muted)]">{m.role}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Recent analyses */}
      <section>
        <h2 className="section-label">Recent analyses</h2>
        {ws.recent_analyses.length === 0 ? (
          <p className="text-[var(--muted)] text-sm">
            No analyses yet. Submit with <code className="font-mono text-xs bg-[var(--border)] px-1 py-0.5 rounded">workspace_id: &quot;{id}&quot;</code> via the API.
          </p>
        ) : (
          <div className="flex flex-col gap-2">
            {ws.recent_analyses.map((a: { slug: string; command: string; threat_labels: string[]; created_at: string }) => (
              <Link
                key={a.slug}
                href={`/c/${a.slug}`}
                className="border border-[var(--border)] bg-[var(--surface)] rounded-lg px-4 py-3 flex items-start justify-between gap-4 hover:border-[var(--accent)] transition-colors group"
              >
                <div className="flex flex-col gap-1 min-w-0">
                  <span className="font-mono text-xs text-[var(--foreground)] truncate">{a.command}</span>
                  <div className="flex gap-1.5 flex-wrap">
                    {a.threat_labels.map((l) => (
                      <span key={l} className="text-xs text-[var(--danger)] border border-[var(--danger)] border-opacity-40 px-1.5 py-0.5 rounded font-mono">
                        {l}
                      </span>
                    ))}
                  </div>
                </div>
                <span className="text-[var(--muted)] text-xs shrink-0">{new Date(a.created_at).toLocaleDateString()}</span>
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
