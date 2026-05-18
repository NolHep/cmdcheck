import { auth } from "@/auth";
import { NextResponse } from "next/server";
import { backendUrl } from "@/app/lib/api";

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ slug: string }> },
): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user?.email) {
    return NextResponse.json(
      { code: "unauthenticated", detail: "Sign in to delete." },
      { status: 401 },
    );
  }

  const { slug } = await params;
  const headers: Record<string, string> = {
    "X-User-Email": session.user.email,
  };
  if (session.user.role === "admin") {
    const adminSecret = process.env.ADMIN_SECRET;
    if (adminSecret) headers["X-Admin-Secret"] = adminSecret;
  }

  const res = await fetch(`${backendUrl()}/c/${slug}`, {
    method: "DELETE",
    headers,
  });

  const data = await res.json().catch(() => ({}));
  return NextResponse.json(data, { status: res.status });
}
