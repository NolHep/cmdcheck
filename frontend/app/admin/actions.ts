"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/auth";
import { redirect } from "next/navigation";

const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8000";
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
  await fetch(`${backendUrl}/admin/settings/banner`, {
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
  await fetch(`${backendUrl}/admin/bug-reports/${id}`, {
    method: "PATCH",
    headers: adminHeaders(),
    body: JSON.stringify({ status, admin_notes: notes || null }),
  });
  revalidatePath("/admin");
}
