"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/auth";
import { redirect } from "next/navigation";
import { backendUrl } from "@/app/lib/api";

const adminSecret = process.env.ADMIN_SECRET ?? "";

async function requireAdmin() {
  const session = await auth();
  if (!session || session.user?.role !== "admin") redirect("/login");
}

function adminHeaders() {
  return {
    "Content-Type": "application/json",
    "X-Admin-Secret": adminSecret,
  };
}

export async function updateBanner(data: FormData) {
  await requireAdmin();
  await fetch(`${backendUrl()}/admin/settings/banner`, {
    method: "PUT",
    headers: adminHeaders(),
    body: JSON.stringify({
      enabled: data.get("enabled") === "true",
      message: data.get("message") as string,
      type: data.get("type") as string,
    }),
  });
  revalidatePath("/admin");
  revalidatePath("/", "layout");
}

export async function updateBugReport(id: string, status: string, notes: string) {
  await requireAdmin();
  await fetch(`${backendUrl()}/admin/bug-reports/${id}`, {
    method: "PATCH",
    headers: adminHeaders(),
    body: JSON.stringify({ status, admin_notes: notes || null }),
  });
  revalidatePath("/admin");
}

export async function clearAllAnalyses(): Promise<{ deleted: number }> {
  await requireAdmin();
  const res = await fetch(`${backendUrl()}/admin/analyses`, {
    method: "DELETE",
    headers: adminHeaders(),
  });
  if (!res.ok) throw new Error("Failed to clear analyses");
  const data = await res.json();
  revalidatePath("/admin");
  revalidatePath("/recent");
  return { deleted: data.deleted as number };
}
