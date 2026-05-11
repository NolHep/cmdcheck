import Link from "next/link";
import { getRecentAnalyses } from "@/app/lib/api";
import type { RecentItem } from "@/app/lib/api";

export const revalidate = 30;

export default async function RecentPage() {
  let items: RecentItem[] = [];
  let fetchError = false;

  try {
    items = await getRecentAnalyses();
  } catch {
    fetchError = true;
  }

  return (
    <div className="max-w-4xl mx-auto w-full px-4 py-8">
      <div className="mb-6">
        <h1 className="text-xl font-bold tracking-tight">Recent analyses</h1>
        <p className="text-[var(--muted)] text-sm mt-1">
          Public command-line analyses — newest first.
        </p>
      </div>

      {fetchError && (
        <p className="text-[var(--danger)] text-sm border border-[var(--danger)] rounded-lg px-4 py-3">
          Could not load recent analyses. Is the backend running?
        </p>
      )}

      {!fetchError && items.length === 0 && (
        <div className="text-center py-16 text-[var(--muted)]">
          <p className="text-4xl mb-3">—</p>
          <p className="text-sm">No analyses yet. Be the first to paste a command.</p>
          <Link href="/" className="mt-4 inline-block text-[var(--accent)] text-sm hover:underline">
            Analyze a command →
          </Link>
        </div>
      )}

      {items.length > 0 && (
        <div className="flex flex-col divide-y divide-[var(--border)] border border-[var(--border)] rounded-lg overflow-hidden">
          {items.map((item) => (
            <RecentRow key={item.slug} item={item} />
          ))}
        </div>
      )}
    </div>
  );
}

function verdictDot(item: RecentItem): { color: string; title: string } {
  if (item.has_lolbas && item.has_encoding) {
    return { color: "bg-[var(--danger)]", title: "Suspicious — LOLBAS binary + encoded payload" };
  }
  if (item.has_lolbas || item.has_encoding) {
    return { color: "bg-yellow-500", title: item.has_lolbas ? "Notable — known-abused binary" : "Notable — encoded payload" };
  }
  if (item.threat_labels.length > 0) {
    return { color: "bg-yellow-500", title: item.threat_labels.join(", ") };
  }
  return { color: "bg-[var(--border)]", title: "Low signal" };
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function RecentRow({ item }: { item: RecentItem }) {
  const dot = verdictDot(item);
  const truncated = item.command.length > 120
    ? item.command.slice(0, 120) + "…"
    : item.command;

  return (
    <Link
      href={`/c/${item.slug}`}
      className="flex items-start gap-4 px-4 py-3 bg-[var(--surface)] hover:bg-[var(--border)] transition-colors group"
    >
      <div className="mt-1.5 shrink-0">
        <span
          className={`inline-block w-2 h-2 rounded-full ${dot.color}`}
          title={dot.title}
        />
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-mono text-xs text-[var(--foreground)] truncate group-hover:text-[var(--accent)] transition-colors">
          {truncated}
        </p>
        {item.threat_labels.length > 0 && (
          <div className="flex gap-1.5 mt-1 flex-wrap">
            {item.threat_labels.slice(0, 3).map((label) => (
              <span
                key={label}
                className="text-[10px] text-[var(--muted)] bg-[var(--background)] border border-[var(--border)] px-1.5 py-0.5 rounded"
              >
                {label}
              </span>
            ))}
          </div>
        )}
      </div>
      <div className="shrink-0 text-[var(--muted)] text-xs tabular-nums whitespace-nowrap">
        {timeAgo(item.created_at)}
      </div>
    </Link>
  );
}
