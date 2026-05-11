import { auth } from "@/auth";
import { NextResponse } from "next/server";

const backend = process.env.BACKEND_URL ?? "http://localhost:8000";

export async function GET(): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) return NextResponse.json({ code: "unauthenticated" }, { status: 401 });

  const res = await fetch(`${backend}/api-keys?email=${encodeURIComponent(session.user.email)}`, { cache: "no-store" });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}

export async function POST(request: Request): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) return NextResponse.json({ code: "unauthenticated" }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const res = await fetch(`${backend}/api-keys`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: session.user.email, name: body.name }),
  });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}

export async function DELETE(request: Request): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) return NextResponse.json({ code: "unauthenticated" }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const res = await fetch(`${backend}/api-keys/${body.id}`, {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: session.user.email }),
  });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
