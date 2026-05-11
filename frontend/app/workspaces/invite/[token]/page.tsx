import type { Metadata } from "next";
import { auth } from "@/auth";
import { redirect } from "next/navigation";
import AcceptInviteButton from "./AcceptInviteButton";

export const metadata: Metadata = { title: "Workspace invite — cmdcheck" };

const backend = process.env.BACKEND_URL ?? "http://localhost:8000";

async function getInvite(token: string) {
  try {
    const res = await fetch(`${backend}/workspaces/invite/${token}`, { cache: "no-store" });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export default async function AcceptInvitePage({
  params,
}: {
  params: Promise<{ token: string }>;
}) {
  const { token } = await params;
  const session = await auth();
  if (!session?.user) redirect(`/login?next=/workspaces/invite/${token}`);

  const invite = await getInvite(token);

  if (!invite || invite.accepted) {
    return (
      <div className="max-w-md mx-auto w-full px-4 py-24 flex flex-col items-center gap-4 text-center">
        <p className="text-5xl text-[var(--border)]">×</p>
        <h1 className="text-xl font-bold">Invite not found</h1>
        <p className="text-[var(--muted)] text-sm">This invite link is invalid, expired, or has already been used.</p>
      </div>
    );
  }

  const isForMe = invite.email === session.user.email;

  return (
    <div className="max-w-md mx-auto w-full px-4 py-24 flex flex-col items-center gap-6 text-center">
      <div className="text-5xl">✉</div>
      <div>
        <h1 className="text-xl font-bold">You&apos;ve been invited</h1>
        <p className="text-[var(--muted)] text-sm mt-2">
          Join workspace <strong className="text-[var(--foreground)]">{invite.workspace_name}</strong>
        </p>
      </div>

      {!isForMe ? (
        <p className="text-[var(--danger)] text-sm">
          This invite was sent to <strong>{invite.email}</strong>, but you&apos;re signed in as{" "}
          <strong>{session.user.email}</strong>.
        </p>
      ) : (
        <AcceptInviteButton token={token} workspaceId={invite.workspace_id} />
      )}
    </div>
  );
}
