import { auth } from "@/auth";
import { redirect } from "next/navigation";
import Link from "next/link";
import TunerClient from "./TunerClient";
import { backendUrl } from "@/app/lib/api";
import type { TuningState } from "./types";

export const metadata = { title: "Detection tuner — ShellHawk admin" };

const adminSecret = process.env.ADMIN_SECRET ?? "";

async function getTuning(): Promise<TuningState | null> {
  try {
    const res = await fetch(`${backendUrl()}/admin/tuning`, {
      headers: { "X-Admin-Secret": adminSecret },
      cache: "no-store",
    });
    if (!res.ok) return null;
    return (await res.json()) as TuningState;
  } catch {
    return null;
  }
}

export default async function TunerPage() {
  const session = await auth();
  if (!session || session.user?.role !== "admin") redirect("/login");

  const state = await getTuning();

  return (
    <div className="max-w-6xl mx-auto w-full px-4 py-8 flex flex-col gap-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold">Detection tuner</h1>
          <p className="text-[var(--muted)] text-sm mt-1 max-w-2xl">
            Adjust how findings are weighted and where each verdict starts. Changes apply site-wide to
            analyses made after you save; existing permalinks keep the verdict they were given.
          </p>
        </div>
        <Link
          href="/admin"
          className="text-sm text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
        >
          ← Admin dashboard
        </Link>
      </div>

      {state ? (
        <TunerClient initial={state} />
      ) : (
        <div className="border border-[var(--danger)] rounded-lg px-4 py-3 text-sm">
          Could not load the tuning from the analysis backend. Check that it is running and that
          ADMIN_SECRET matches on both sides.
        </div>
      )}
    </div>
  );
}
