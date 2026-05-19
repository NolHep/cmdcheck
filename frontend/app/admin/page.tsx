import { auth } from "@/auth";
import { redirect } from "next/navigation";
import Link from "next/link";
import { updateBanner, updateBugReport } from "./actions";
import { backendUrl } from "@/app/lib/api";
import ClearAnalysesButton from "./ClearAnalysesButton";

const adminSecret = process.env.ADMIN_SECRET ?? "";

function adminHeaders() {
  return { "Content-Type": "application/json", "X-Admin-Secret": adminSecret };
}

async function getStats() {
  const res = await fetch(`${backendUrl()}/admin/stats`, {
    headers: adminHeaders(),
    next: { revalidate: 60 },
  });
  if (!res.ok) return null;
  return res.json();
}

async function getBugReports() {
  const res = await fetch(`${backendUrl()}/admin/bug-reports`, {
    headers: adminHeaders(),
    next: { revalidate: 0 },
  });
  if (!res.ok) return [];
  return res.json();
}

async function getBanner() {
  const res = await fetch(`${backendUrl()}/settings/banner`, {
    next: { revalidate: 10 },
  });
  if (!res.ok) return { enabled: false, message: "", type: "info" };
  return res.json();
}

const SEVERITY_STYLE: Record<string, string> = {
  high: "text-[var(--danger)] border-[var(--danger)]",
  medium: "text-yellow-400 border-yellow-600",
  low: "text-[var(--muted)] border-[var(--border)]",
};

const STATUS_STYLE: Record<string, string> = {
  open: "text-[var(--danger)]",
  triaging: "text-yellow-400",
  resolved: "text-[var(--success)]",
  closed: "text-[var(--muted)]",
};

export default async function AdminPage() {
  const session = await auth();
  if (!session || session.user?.role !== "admin") redirect("/login");

  const [stats, bugReports, banner] = await Promise.all([getStats(), getBugReports(), getBanner()]);

  return (
    <div className="max-w-4xl mx-auto w-full px-4 py-8 flex flex-col gap-10">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold">Admin Dashboard</h1>
          <p className="text-[var(--muted)] text-sm mt-1">Signed in as {session.user?.email}</p>
        </div>
        <Link
          href="/admin/threat-map"
          className="text-sm px-3 py-1.5 border border-[var(--border)] rounded-lg text-[var(--muted)] hover:text-[var(--foreground)] hover:border-[var(--accent)] transition-colors"
        >
          Threat Actor Map →
        </Link>
      </div>

      {/* Stats */}
      {stats && (
        <section>
          <h2 className="section-label mb-4">Overview</h2>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {[
              { label: "Total analyses", value: stats.total_analyses },
              { label: "Today", value: stats.today_analyses },
              { label: "This week", value: stats.week_analyses },
              { label: "Users", value: stats.total_users },
              { label: "Open bugs", value: stats.open_bugs },
            ].map((s) => (
              <div key={s.label} className="border border-[var(--border)] rounded-lg px-4 py-3 bg-[var(--surface)]">
                <p className="text-2xl font-bold text-[var(--foreground)]">{s.value}</p>
                <p className="text-xs text-[var(--muted)] mt-0.5">{s.label}</p>
              </div>
            ))}
          </div>
          {stats.top_threat_classes.length > 0 && (
            <div className="mt-4 border border-[var(--border)] rounded-lg overflow-hidden">
              <div className="px-4 py-2 bg-[var(--surface)] border-b border-[var(--border)]">
                <span className="text-xs text-[var(--muted)] font-semibold uppercase tracking-wide">Top threat behaviors</span>
              </div>
              {stats.top_threat_classes.map((t: { label: string; count: number }) => (
                <div key={t.label} className="flex items-center justify-between px-4 py-2 border-b border-[var(--border)] last:border-0">
                  <span className="text-sm text-[var(--foreground)]">{t.label}</span>
                  <span className="text-sm font-mono text-[var(--muted)]">{t.count}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Site banner */}
      <section>
        <h2 className="section-label mb-4">Site Banner</h2>
        <div className="border border-[var(--border)] rounded-lg p-4">
          <form action={updateBanner} className="flex flex-col gap-4">
            <div className="flex items-center gap-3">
              <label className="text-sm text-[var(--muted)]">Enabled</label>
              <select
                name="enabled"
                defaultValue={banner.enabled ? "true" : "false"}
                className="bg-[var(--surface)] border border-[var(--border)] rounded px-2 py-1 text-sm text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)]"
              >
                <option value="false">Off</option>
                <option value="true">On</option>
              </select>
              <select
                name="type"
                defaultValue={banner.type}
                className="bg-[var(--surface)] border border-[var(--border)] rounded px-2 py-1 text-sm text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)]"
              >
                <option value="info">Info</option>
                <option value="warning">Warning</option>
                <option value="danger">Danger</option>
              </select>
            </div>
            <textarea
              name="message"
              defaultValue={banner.message}
              rows={2}
              placeholder="Banner message shown to all users…"
              className="bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)] resize-none"
            />
            <button
              type="submit"
              className="self-start px-4 py-1.5 bg-[var(--accent)] text-[#0d1117] text-sm font-semibold rounded-lg hover:brightness-110 transition-all"
            >
              Save banner
            </button>
          </form>
        </div>
      </section>

      {/* Danger zone */}
      <section>
        <h2 className="section-label mb-4">Danger Zone</h2>
        <div className="border border-[var(--danger)] rounded-lg p-4 flex items-start justify-between gap-4 flex-wrap">
          <div>
            <p className="text-sm font-semibold text-[var(--foreground)]">Clear all analyses</p>
            <p className="text-xs text-[var(--muted)] mt-0.5">
              Soft-deletes every public analysis. Slugs become tombstones. Irreversible via UI.
            </p>
          </div>
          <ClearAnalysesButton />
        </div>
      </section>

      {/* Bug reports */}
      <section>
        <h2 className="section-label mb-4">Bug Reports ({bugReports.length})</h2>
        {bugReports.length === 0 ? (
          <p className="text-[var(--muted)] text-sm">No bug reports yet.</p>
        ) : (
          <div className="flex flex-col gap-3">
            {bugReports.map((r: {
              id: string; title: string; description: string; severity: string;
              status: string; contact_email: string | null; admin_notes: string | null; created_at: string;
            }) => (
              <div key={r.id} className="border border-[var(--border)] rounded-lg overflow-hidden">
                <div className="px-4 py-3 bg-[var(--surface)] border-b border-[var(--border)] flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-sm text-[var(--foreground)]">{r.title}</span>
                      <span className={`text-xs border px-1.5 py-0.5 rounded ${SEVERITY_STYLE[r.severity]}`}>{r.severity}</span>
                      <span className={`text-xs font-semibold ${STATUS_STYLE[r.status]}`}>{r.status}</span>
                    </div>
                    {r.contact_email && (
                      <p className="text-xs text-[var(--muted)] mt-0.5">{r.contact_email}</p>
                    )}
                  </div>
                  <span className="text-xs text-[var(--muted)] shrink-0">{new Date(r.created_at).toLocaleDateString()}</span>
                </div>
                <div className="px-4 py-3">
                  <p className="text-sm text-[var(--muted)] whitespace-pre-wrap">{r.description}</p>
                  {r.admin_notes && (
                    <p className="text-xs text-[var(--accent)] mt-2 border-t border-[var(--border)] pt-2">
                      Notes: {r.admin_notes}
                    </p>
                  )}
                  <form
                    action={async (data: FormData) => {
                      "use server";
                      await updateBugReport(r.id, data.get("status") as string, data.get("notes") as string);
                    }}
                    className="flex items-center gap-2 mt-3 flex-wrap"
                  >
                    <select
                      name="status"
                      defaultValue={r.status}
                      className="bg-[var(--surface)] border border-[var(--border)] rounded px-2 py-1 text-xs text-[var(--foreground)] focus:outline-none"
                    >
                      {["open", "triaging", "resolved", "closed"].map((s) => (
                        <option key={s} value={s}>{s}</option>
                      ))}
                    </select>
                    <input
                      name="notes"
                      defaultValue={r.admin_notes ?? ""}
                      placeholder="Admin notes…"
                      className="flex-1 min-w-0 bg-[var(--surface)] border border-[var(--border)] rounded px-2 py-1 text-xs text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)]"
                    />
                    <button
                      type="submit"
                      className="text-xs px-3 py-1 bg-[var(--accent)] text-[#0d1117] font-semibold rounded hover:brightness-110"
                    >
                      Update
                    </button>
                  </form>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
