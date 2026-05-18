import { auth } from "@/auth";
import { NextResponse } from "next/server";
import { backendUrl } from "@/app/lib/api";

export async function POST(request: Request): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) {
    return NextResponse.json(
      { code: "unauthenticated", detail: "Sign in to manage your subscription." },
      { status: 401 },
    );
  }

  const origin = new URL(request.url).origin;

  const res = await fetch(`${backendUrl()}/billing/portal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: session.user.email,
      return_url: `${origin}/pricing`,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    return NextResponse.json(err, { status: res.status });
  }

  const data = await res.json();
  return NextResponse.json(data);
}
