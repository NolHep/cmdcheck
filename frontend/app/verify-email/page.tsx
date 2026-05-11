import Link from "next/link";

const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8000";

export const dynamic = "force-dynamic";

export default async function VerifyEmailPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  const { token } = await searchParams;

  if (!token) {
    return <Result ok={false} message="No verification token provided." />;
  }

  let ok = false;
  try {
    const res = await fetch(`${backendUrl}/auth/verify-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
      cache: "no-store",
    });
    ok = res.ok;
  } catch {
    ok = false;
  }

  return ok ? (
    <Result
      ok
      message="Your email address has been verified. You can now sign in."
    />
  ) : (
    <Result
      ok={false}
      message="This verification link has expired or already been used."
    />
  );
}

function Result({ ok, message }: { ok: boolean; message: string }) {
  return (
    <div className="max-w-sm mx-auto w-full px-4 py-20 flex flex-col items-center gap-4 text-center">
      <p className={`text-5xl ${ok ? "text-[var(--success)]" : "text-[var(--danger)]"}`}>
        {ok ? "✓" : "✗"}
      </p>
      <h1 className="text-xl font-bold">{ok ? "Email verified" : "Verification failed"}</h1>
      <p className="text-[var(--muted)] text-sm">{message}</p>
      {ok ? (
        <Link href="/login" className="text-[var(--accent)] text-sm hover:underline">
          Sign in →
        </Link>
      ) : (
        <Link href="/login" className="text-[var(--accent)] text-sm hover:underline">
          Back to sign in
        </Link>
      )}
    </div>
  );
}
