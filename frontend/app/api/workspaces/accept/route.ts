import { auth } from "@/auth";
import { NextResponse } from "next/server";

const backend = process.env.BACKEND_URL ?? "http://localhost:8000";

export async function POST(request: Request): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) return NextResponse.json({ code: "unauthenticated" }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const res = await fetch(`${backend}/workspaces/accept/${body.token}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: body.token, user_email: session.user.email }),
  });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
