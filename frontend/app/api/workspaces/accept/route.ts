import { auth } from "@/auth";
import { NextResponse } from "next/server";
import { z } from "zod";
import { backendUrl } from "@/app/lib/api";

const AcceptInviteSchema = z.object({
  token: z.string().min(1).max(256),
});

export async function POST(request: Request): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) return NextResponse.json({ code: "unauthenticated" }, { status: 401 });

  const raw = await request.json().catch(() => null);
  const parsed = AcceptInviteSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json({ code: "invalid_input", detail: parsed.error.issues }, { status: 400 });
  }

  const res = await fetch(`${backendUrl()}/workspaces/accept/${parsed.data.token}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: parsed.data.token, user_email: session.user.email }),
  });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
