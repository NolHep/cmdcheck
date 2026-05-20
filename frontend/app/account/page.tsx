import type { Metadata } from "next";
import { auth } from "@/auth";
import { redirect } from "next/navigation";
import Link from "next/link";
import { backendUrl } from "@/app/lib/api";
import type { RecentItem } from "@/app/lib/api";

export const metadata: Metadata = { title: "Account — ShellHawk" };

async function getAnalyses(email: string): Promise<RecentItem[]> {
  try {
    const res = await fetch(`${backendUrl()}/user/analyses`, {
      headers: { "X-User-Email": email },
      cache: "no-store",
    });
    if (!res.ok) return [];
    return res.json();
  } catch {
    return [];
  }
}

export default async function AccountPage() {
  const session = await auth();
  if (!session?.user) redirect("/login?next=/account");

  const analyses = await getAnalyses(session.user.email!);

  return (
    <div className="max-w-3xl mx-auto w-full px-4 py-10 flex flex-col gap-8">

      {/* Profile */}
      <div className="border border-[var(--border)] rounded-lg px-5 py-4 bg-[var(--surface)] flex flex-col gap-2">
        <p className="text-xs text-[var(--muted)] uppercase tracking-wide font-semibold">Profile</p>
        <p className="font-semibold">{session.user.email}</p>
        <p className="text-xs text-[var(--muted)] capitalize">{session.user.role ?? "user"} account</p>
      </div>

      {/* Quick links */}
      <div className="flex flex-wrap gap-3">
        <Link
          href="/account/api-keys"
          className="px-4 py-2 bg-[var(--surface)] border border-[var(--border)] rounded-lg text-sm hover:border-[var(--accent)] transition-colors"
        >
          API keys →
        </Link>
        <Link
          href="/workspaces"
          className="px-4 py-2 bg-[var(--surface)] border border-[var(--border)] rounded-lg text-sm hover:border-[var(--accent)] transition-colors"
        >
          Workspaces →
        </Link>
      </div>

      {/* Analyses */}
      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-[var(--muted)] uppercase tracking-wide">
          Your analyses ({analyses.length})
        </h2>
        {analyses.length === 0 ? (
          <div className="border border-[var(--border)] rounded-lg px-5 py-8 text-center text-[var(--muted)] text-sm">
            No analyses yet.{" "}
            <Link href="/" className="text-[var(--accent)] hover:underline">
              Analyze a command →
            </Link>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {analyses.map((a) => (
              <Link
                key={a.slug}
                href={`/c/${a.slug}`}
                className="border border-[var(--border)] rounded-lg px-4 py-3 bg-[var(--surface)] hover:border-[var(--accent)] transition-colors flex flex-col gap-1"
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs text-[var(--foreground)] truncate flex-1">
                    {a.command}
                  </span>
                  {("is_private" in a && (a as RecentItem & { is_private?: boolean }).is_private) && (
                    <span className="text-xs px-1.5 py-0.5 rounded border border-[var(--border)] text-[var(--muted)] font-mono shrink-0">
                      private
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  {a.threat_labels.map((label) => (
                    <span
                      key={label}
                      className="text-xs bg-[#3d1a1a] text-[var(--danger)] border border-[var(--danger)] border-opacity-30 px-1.5 py-0.5 rounded"
                    >
                      {label}
                    </span>
                  ))}
                  {a.has_lolbas && (
                    <span className="text-xs bg-[var(--border)] text-[var(--muted)] px-1.5 py-0.5 rounded">LOLBAS</span>
                  )}
                  {a.has_encoding && (
                    <span className="text-xs bg-[var(--border)] text-[var(--muted)] px-1.5 py-0.5 rounded">Encoded</span>
                  )}
                  <span className="text-xs text-[var(--muted)] ml-auto">
                    {new Date(a.created_at).toLocaleDateString()}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
