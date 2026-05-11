import { auth } from "@/auth";
import { NextResponse } from "next/server";

const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8000";

export async function POST(request: Request): Promise<NextResponse> {
  const session = await auth();
  const body = await request.json().catch(() => ({}));

  const { command, parent_process, is_private, skip_redaction, workspace_id } = body as {
    command?: string;
    parent_process?: string | null;
    is_private?: boolean;
    skip_redaction?: boolean;
    workspace_id?: string | null;
  };

  if (!command) {
    return NextResponse.json({ code: "missing_command", detail: "command is required" }, { status: 400 });
  }

  if (is_private && !session?.user?.email) {
    return NextResponse.json(
      { code: "unauthenticated", detail: "Sign in to submit privately." },
      { status: 401 },
    );
  }

  const res = await fetch(`${backendUrl}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      command,
      parent_process: parent_process ?? null,
      is_private: !!is_private,
      skip_redaction: !!skip_redaction,
      workspace_id: workspace_id ?? null,
      user_email: session?.user?.email ?? null,
    }),
  });

  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
