"use server";

import { auth } from "@/auth";
import { redirect } from "next/navigation";
import { backendUrl } from "@/app/lib/api";
import type { BenchmarkResult, PreviewResult, Tuning, TuningState } from "./types";

const adminSecret = process.env.ADMIN_SECRET ?? "";

async function requireAdmin() {
  const session = await auth();
  if (!session || session.user?.role !== "admin") redirect("/login");
}

function headers() {
  return { "Content-Type": "application/json", "X-Admin-Secret": adminSecret };
}

export type ActionResult<T> = { ok: true; data: T } | { ok: false; error: string };

// The backend answers errors as {code, detail: [{field, message}]} for
// validation and {detail: {code, detail}} for everything else.
async function errorText(res: Response): Promise<string> {
  const body = await res.json().catch(() => null);
  const detail = body?.detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d: { field?: string; message?: string }) => `${d.field ? `${d.field}: ` : ""}${d.message ?? "invalid"}`)
      .join("; ");
  }
  if (typeof detail?.detail === "string") return detail.detail;
  if (typeof detail === "string") return detail;
  return `Request failed (${res.status})`;
}

async function call<T>(path: string, init: RequestInit): Promise<ActionResult<T>> {
  await requireAdmin();
  try {
    const res = await fetch(`${backendUrl()}${path}`, { ...init, headers: headers(), cache: "no-store" });
    if (!res.ok) return { ok: false, error: await errorText(res) };
    return { ok: true, data: (await res.json()) as T };
  } catch {
    return { ok: false, error: "Could not reach the analysis backend." };
  }
}

export async function saveTuning(tuning: Tuning) {
  return call<TuningState>("/admin/tuning", { method: "PUT", body: JSON.stringify(tuning) });
}

export async function resetTuning() {
  return call<TuningState>("/admin/tuning", { method: "DELETE" });
}

export async function previewTuning(command: string, tuning: Tuning) {
  return call<PreviewResult>("/admin/tuning/preview", {
    method: "POST",
    body: JSON.stringify({ command, tuning }),
  });
}

export async function benchmarkTuning(tuning: Tuning) {
  return call<BenchmarkResult>("/admin/tuning/benchmark", {
    method: "POST",
    body: JSON.stringify({ tuning }),
  });
}
