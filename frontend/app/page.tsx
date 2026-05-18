import Link from "next/link";
import { auth } from "@/auth";
import HomeContent from "@/app/components/HomeContent";
import AnalysisTicker from "@/app/components/AnalysisTicker";
import { backendUrl } from "@/app/lib/api";

async function getUserWorkspaces(email: string): Promise<{ id: string; name: string }[]> {
  try {
    const res = await fetch(
      `${backendUrl()}/workspaces/mine?email=${encodeURIComponent(email)}`,
      { cache: "no-store" },
    );
    if (!res.ok) return [];
    const data = await res.json();
    return data.map((w: { id: string; name: string }) => ({ id: w.id, name: w.name }));
  } catch {
    return [];
  }
}

async function getAnalysisCount(): Promise<number> {
  try {
    const res = await fetch(`${backendUrl()}/stats/count`, { next: { revalidate: 60 } });
    if (!res.ok) return 0;
    const data = await res.json();
    return data.count ?? 0;
  } catch {
    return 0;
  }
}

export default async function HomePage() {
  const session = await auth();
  const loggedIn = !!session?.user;
  const [workspaces, analysisCount] = await Promise.all([
    loggedIn && session.user?.email ? getUserWorkspaces(session.user.email) : Promise.resolve([]),
    getAnalysisCount(),
  ]);

  return (
    <div className="flex-1 flex flex-col items-center justify-start px-4 py-12 gap-8 max-w-3xl mx-auto w-full">
      <div className="text-center">
        <h1 className="text-3xl font-bold tracking-tight mb-2">
          Command-line analyzer
        </h1>
        <p className="text-[var(--muted)] text-base">
          Paste a suspicious command. Get deobfuscation, LOLBAS matching, and a
          shareable permalink — instantly.
        </p>
        {analysisCount > 0 && (
          <p className="text-[var(--muted)] text-sm mt-3">
            <AnalysisTicker count={analysisCount} /> commands analyzed and counting
          </p>
        )}
      </div>
      <HomeContent loggedIn={loggedIn} workspaces={workspaces} />
      <div className="w-full border-t border-[var(--border)] pt-6 flex items-center justify-between gap-4">
        <p className="text-[var(--muted)] text-xs">
          Need private submissions, higher limits, or team workspaces?
        </p>
        <Link
          href="/pricing"
          className="text-xs text-[var(--accent)] hover:underline shrink-0"
        >
          See paid plans →
        </Link>
      </div>
    </div>
  );
}
