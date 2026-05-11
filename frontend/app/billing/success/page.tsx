import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Subscription active — cmdcheck" };

export default function BillingSuccessPage() {
  return (
    <div className="max-w-md mx-auto w-full px-4 py-24 flex flex-col items-center gap-6 text-center">
      <div className="text-5xl">✓</div>
      <h1 className="text-2xl font-bold">You&apos;re subscribed</h1>
      <p className="text-[var(--muted)] text-sm leading-relaxed">
        Payment confirmed. Your plan is now active — private submissions and
        higher rate limits are enabled on your account.
      </p>
      <p className="text-[var(--muted)] text-xs">
        A receipt has been sent to your email. Manage your plan anytime from
        the{" "}
        <Link href="/pricing" className="text-[var(--accent)] hover:underline">
          pricing page
        </Link>
        .
      </p>
      <Link
        href="/"
        className="mt-2 px-6 py-2.5 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg text-sm hover:brightness-110 transition-all"
      >
        Start analyzing →
      </Link>
    </div>
  );
}
