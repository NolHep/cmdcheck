import { NextResponse } from "next/server";
import { z } from "zod";
import { backendUrl } from "@/app/lib/api";

const FeedbackSchema = z.object({
  title: z.string().min(3).max(200),
  description: z.string().min(10).max(5000),
  severity: z.enum(["low", "medium", "high"]).default("medium"),
  contact_email: z.string().email().nullable().optional(),
});

export async function POST(request: Request): Promise<NextResponse> {
  const raw = await request.json().catch(() => null);
  const parsed = FeedbackSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json({ code: "invalid_input", detail: "Please fill in all required fields." }, { status: 400 });
  }

  const res = await fetch(`${backendUrl()}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      title: parsed.data.title,
      description: parsed.data.description,
      severity: parsed.data.severity,
      contact_email: parsed.data.contact_email ?? null,
    }),
  });

  const data = await res.json().catch(() => ({}));
  return NextResponse.json(data, { status: res.status });
}
