import { auth } from "@/auth";
import { redirect } from "next/navigation";
import Link from "next/link";
import ThreatMapClient from "./ThreatMapClient";
import { backendUrl } from "@/app/lib/api";

const adminSecret = process.env.ADMIN_SECRET ?? "";

async function getGroups() {
  const res = await fetch(`${backendUrl()}/admin/threat-groups`, {
    headers: { "X-Admin-Secret": adminSecret },
    cache: "no-store",
  });
  if (!res.ok) return [];
  return res.json();
}

export default async function ThreatMapPage() {
  const session = await auth();
  if (!session || session.user?.role !== "admin") redirect("/login");

  const groups = await getGroups();

  return (
    <div className="max-w-4xl mx-auto w-full px-4 py-8 flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold">Threat Actor Map</h1>
          <p className="text-[var(--muted)] text-sm mt-1">
            Manually group analyses by threat actor or campaign. Links are never automatic.
          </p>
        </div>
        <Link
          href="/admin"
          className="text-sm text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
        >
          ← Admin dashboard
        </Link>
      </div>

      <ThreatMapClient initialGroups={groups} />
    </div>
  );
}
