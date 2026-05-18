import { auth } from "@/auth";
import { NextResponse } from "next/server";
import { backendUrl } from "@/app/lib/api";

export async function POST(request: Request): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) {
    return NextResponse.json(
      { code: "unauthenticated", detail: "Sign in to subscribe." },
      { status: 401 },
    );
  }

  const body = await request.json().catch(() => ({}));
  const tier = body?.tier as string | undefined;
  if (tier !== "individual" && tier !== "teams") {
    return NextResponse.json(
      { code: "invalid_tier", detail: "Invalid tier." },
      { status: 400 },
    );
  }

  const origin = new URL(request.url).origin;

  const res = await fetch(`${backendUrl()}/billing/checkout`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: session.user.email,
      tier,
      success_url: `${origin}/billing/success`,
      cancel_url: `${origin}/pricing`,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    return NextResponse.json(err, { status: res.status });
  }

  const data = await res.json();
  return NextResponse.json(data);
}
