import { auth } from "@/auth";
import { NextResponse } from "next/server";
import { z } from "zod";

const backend = process.env.BACKEND_URL ?? "http://localhost:8000";

const InviteSchema = z.object({
  invite_email: z.string().email(),
});

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) return NextResponse.json({ code: "unauthenticated" }, { status: 401 });

  const { id } = await params;
  const raw = await request.json().catch(() => null);
  const parsed = InviteSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json({ code: "invalid_input", detail: parsed.error.issues }, { status: 400 });
  }

  const res = await fetch(`${backend}/workspaces/${id}/invite`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ owner_email: session.user.email, invite_email: parsed.data.invite_email }),
  });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
