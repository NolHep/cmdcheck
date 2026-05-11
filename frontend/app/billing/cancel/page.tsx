import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Checkout cancelled — cmdcheck" };

export default function BillingCancelPage() {
  return (
    <div className="max-w-md mx-auto w-full px-4 py-24 flex flex-col items-center gap-6 text-center">
      <div className="text-5xl text-[var(--muted)]">×</div>
      <h1 className="text-2xl font-bold">Checkout cancelled</h1>
      <p className="text-[var(--muted)] text-sm">
        No charge was made. You can subscribe any time from the pricing page.
      </p>
      <div className="flex gap-3">
        <Link
          href="/pricing"
          className="px-5 py-2 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg text-sm hover:brightness-110 transition-all"
        >
          Back to pricing
        </Link>
        <Link
          href="/"
          className="px-5 py-2 border border-[var(--border)] text-[var(--foreground)] rounded-lg text-sm hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors"
        >
          Analyze a command
        </Link>
      </div>
    </div>
  );
}
