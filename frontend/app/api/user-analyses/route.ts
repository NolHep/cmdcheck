import { auth } from "@/auth";
import { NextResponse } from "next/server";
import { backendUrl } from "@/app/lib/api";

export async function GET(): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) {
    return NextResponse.json(
      { code: "unauthenticated", detail: "Sign in required." },
      { status: 401 },
    );
  }

  const res = await fetch(`${backendUrl()}/user/analyses`, {
    headers: { "X-User-Email": session.user.email },
    cache: "no-store",
  });

  const data = await res.json().catch(() => []);
  return NextResponse.json(data, { status: res.status });
}
