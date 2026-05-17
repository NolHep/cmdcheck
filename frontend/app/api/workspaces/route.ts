import { auth } from "@/auth";
import { NextResponse } from "next/server";
import { z } from "zod";

const backend = process.env.BACKEND_URL ?? "http://localhost:8000";

const CreateWorkspaceSchema = z.object({
  name: z.string().min(1).max(100),
});

export async function GET(): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) return NextResponse.json({ code: "unauthenticated" }, { status: 401 });

  const res = await fetch(`${backend}/workspaces/mine?email=${encodeURIComponent(session.user.email)}`, { cache: "no-store" });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}

export async function POST(request: Request): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) return NextResponse.json({ code: "unauthenticated" }, { status: 401 });

  const raw = await request.json().catch(() => null);
  const parsed = CreateWorkspaceSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json({ code: "invalid_input", detail: parsed.error.issues }, { status: 400 });
  }

  const res = await fetch(`${backend}/workspaces`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: session.user.email, name: parsed.data.name }),
  });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
