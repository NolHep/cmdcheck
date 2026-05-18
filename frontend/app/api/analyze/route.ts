import { auth } from "@/auth";
import { NextResponse } from "next/server";
import { z } from "zod";
import { backendUrl } from "@/app/lib/api";

const AnalyzeBodySchema = z.object({
  command: z.string().min(1).max(65536),
  parent_process: z.string().max(256).nullable().optional(),
  is_private: z.boolean().optional(),
  skip_redaction: z.boolean().optional(),
  workspace_id: z.string().uuid().nullable().optional(),
});

export async function POST(request: Request): Promise<NextResponse> {
  const session = await auth();
  const raw = await request.json().catch(() => null);
  const parsed = AnalyzeBodySchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json({ code: "invalid_input", detail: parsed.error.issues }, { status: 400 });
  }

  const { command, parent_process, is_private, skip_redaction, workspace_id } = parsed.data;

  if (is_private && !session?.user?.email) {
    return NextResponse.json(
      { code: "unauthenticated", detail: "Sign in to submit privately." },
      { status: 401 },
    );
  }

  // skip_redaction requires an authenticated session — anonymous users cannot
  // disable the credential/IP redaction pass on public commands.
  const effective_skip_redaction = !!skip_redaction && !!session?.user?.email;

  const res = await fetch(`${backendUrl()}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      command,
      parent_process: parent_process ?? null,
      is_private: !!is_private,
      skip_redaction: effective_skip_redaction,
      workspace_id: workspace_id ?? null,
      user_email: session?.user?.email ?? null,
    }),
  });

  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
