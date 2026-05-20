import type { Metadata } from "next";
import Link from "next/link";
import { auth } from "@/auth";
import { redirect } from "next/navigation";
import { backendUrl } from "@/app/lib/api";

export const metadata: Metadata = { title: "Workspaces — ShellHawk" };

async function getWorkspaces(email: string) {
  try {
    const res = await fetch(`${backendUrl()}/workspaces/mine?email=${encodeURIComponent(email)}`, { cache: "no-store" });
    if (!res.ok) return [];
    return res.json();
  } catch {
    return [];
  }
}

export default async function WorkspacesPage() {
  const session = await auth();
  if (!session?.user) redirect("/login?next=/workspaces");

  const workspaces = await getWorkspaces(session.user.email!);

  return (
    <div className="max-w-3xl mx-auto w-full px-4 py-10 flex flex-col gap-8">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Workspaces</h1>
          <p className="text-[var(--muted)] text-sm mt-1">Share analyses with your incident response team.</p>
        </div>
        <Link
          href="/workspaces/new"
          className="px-4 py-2 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg text-sm hover:brightness-110 transition-all shrink-0"
        >
          New workspace
        </Link>
      </div>

      {workspaces.length === 0 ? (
        <div className="border border-[var(--border)] rounded-xl px-6 py-12 flex flex-col items-center gap-4 text-center bg-[var(--surface)]">
          <p className="text-[var(--muted)] text-sm">You are not a member of any workspaces yet.</p>
          <Link href="/workspaces/new" className="text-[var(--accent)] text-sm hover:underline">
            Create your first workspace →
          </Link>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {workspaces.map((ws: { id: string; name: string; role: string; member_count: number; created_at: string }) => (
            <Link
              key={ws.id}
              href={`/workspaces/${ws.id}`}
              className="border border-[var(--border)] bg-[var(--surface)] rounded-lg px-5 py-4 flex items-center justify-between gap-4 hover:border-[var(--accent)] transition-colors group"
            >
              <div className="flex flex-col gap-0.5">
                <span className="font-semibold text-sm group-hover:text-[var(--accent)] transition-colors">{ws.name}</span>
                <span className="text-[var(--muted)] text-xs">
                  {ws.member_count} {ws.member_count === 1 ? "member" : "members"} · {ws.role}
                </span>
              </div>
              <span className="text-[var(--muted)] text-xs shrink-0">{new Date(ws.created_at).toLocaleDateString()}</span>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
