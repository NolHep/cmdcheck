import type { Metadata } from "next";
import Link from "next/link";
import { auth } from "@/auth";
import CheckoutButton from "@/app/components/CheckoutButton";
import ManageSubscriptionButton from "@/app/components/ManageSubscriptionButton";

export const metadata: Metadata = {
  title: "Pricing — cmdcheck",
  description:
    "Free for public analysis. Paid plans add private submissions, higher API limits, team workspaces, and beta enrichment features.",
};

const TIERS = [
  {
    name: "Individual",
    price: "$9.99",
    period: "/month",
    tagline: "For analysts who need privacy and speed.",
    featured: false,
    tier: "individual" as const,
    contactUs: false,
    features: [
      "Private command submissions",
      "120 analyses / minute",
      "Personal analysis history",
      "CSV & JSON export",
      "Email support",
    ],
    note: null,
  },
  {
    name: "Teams",
    price: null,
    period: null,
    tagline: "For incident response teams.",
    featured: true,
    tier: "teams" as const,
    contactUs: true,
    features: [
      "Everything in Individual",
      "Up to 15 team members",
      "Shared analysis library",
      "300 analyses / minute (pooled)",
      "Team dashboard & history",
      "Priority email support",
    ],
    note: "Most popular",
  },
  {
    name: "Organization",
    price: null,
    period: null,
    tagline: "For security operations centers and MSSPs.",
    featured: false,
    tier: null,
    contactUs: true,
    features: [
      "Everything in Teams",
      "Unlimited members",
      "600 analyses / minute (pooled)",
      "API key management",
      "Beta: deep threat enrichment",
      "Beta: YARA rule suggestions",
      "Beta: campaign correlation",
      "Dedicated support channel",
    ],
    note: "Includes beta features",
  },
] as const;

const FREE_FEATURES = [
  "Unlimited public analyses",
  "Base64 / gzip decode pipeline",
  "LOLBAS + GTFOBins matching",
  "MITRE ATT&CK technique mapping",
  "Shareable permalinks",
  "VirusTotal URL lookup",
  "Public corpus search",
];

export default async function PricingPage() {
  const session = await auth();
  const loggedIn = !!session?.user;

  return (
    <div className="max-w-5xl mx-auto w-full px-4 py-14 flex flex-col gap-14">

      {/* Header */}
      <div className="text-center flex flex-col gap-3">
        <h1 className="text-3xl font-bold tracking-tight">Pricing</h1>
        <p className="text-[var(--muted)] text-base max-w-xl mx-auto">
          The core paste-and-analyze workflow is free, forever.
          Paid plans add privacy, higher limits, and team features for professional use.
        </p>
      </div>

      {/* Free tier callout */}
      <div className="border border-[var(--border)] rounded-xl px-6 py-5 flex flex-col sm:flex-row sm:items-center gap-4 bg-[var(--surface)]">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-xl font-bold">Free</span>
            <span className="text-xs font-semibold px-2 py-0.5 rounded border border-[var(--accent)] text-[var(--accent)]">
              Always free
            </span>
          </div>
          <p className="text-[var(--muted)] text-sm mb-3">
            No account required. Submissions are public and indexed in the corpus.
          </p>
          <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-1">
            {FREE_FEATURES.map((f) => (
              <li key={f} className="text-sm text-[var(--muted)] flex items-start gap-2">
                <span className="text-[var(--success)] mt-0.5 shrink-0">✓</span>
                {f}
              </li>
            ))}
          </ul>
        </div>
        <div className="shrink-0">
          <Link
            href="/"
            className="inline-block px-5 py-2 border border-[var(--border)] rounded-lg text-sm font-semibold hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors"
          >
            Start analyzing →
          </Link>
        </div>
      </div>

      {/* Paid tiers */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {TIERS.map((tier) => (
          <div
            key={tier.name}
            className={`relative flex flex-col rounded-xl border px-6 py-6 gap-5 ${
              tier.featured
                ? "border-[var(--accent)] bg-[#0d1a2e]"
                : "border-[var(--border)] bg-[var(--surface)]"
            }`}
          >
            {tier.note && (
              <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                <span className="bg-[var(--accent)] text-[#0d1117] text-xs font-bold px-3 py-1 rounded-full whitespace-nowrap">
                  {tier.note}
                </span>
              </div>
            )}

            <div>
              <p className="text-xs font-semibold uppercase tracking-widest text-[var(--muted)] mb-1">
                {tier.name}
              </p>
              {tier.contactUs ? (
                <div className="flex items-baseline gap-1">
                  <span className="text-2xl font-bold text-[var(--muted)]">Contact us</span>
                </div>
              ) : (
                <div className="flex items-baseline gap-1">
                  <span className="text-3xl font-bold">{tier.price}</span>
                  <span className="text-[var(--muted)] text-sm">{tier.period}</span>
                </div>
              )}
              <p className="text-[var(--muted)] text-sm mt-2">{tier.tagline}</p>
            </div>

            <ul className="flex flex-col gap-2 flex-1">
              {tier.features.map((f) => (
                <li key={f} className="text-sm flex items-start gap-2">
                  <span
                    className={`mt-0.5 shrink-0 ${
                      tier.featured ? "text-[var(--accent)]" : "text-[var(--success)]"
                    }`}
                  >
                    ✓
                  </span>
                  <span className={f.startsWith("Beta:") ? "text-[var(--muted)]" : "text-[var(--foreground)]"}>
                    {f.startsWith("Beta:") ? (
                      <>
                        <span className="text-xs font-semibold text-yellow-500 mr-1">BETA</span>
                        {f.slice(6)}
                      </>
                    ) : f}
                  </span>
                </li>
              ))}
            </ul>

            {tier.contactUs ? (
              <a
                href="mailto:hello@cmdcheck.io"
                className={`w-full py-2.5 rounded-lg font-semibold text-sm border transition-colors text-center block ${
                  tier.featured
                    ? "border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)] hover:text-[#0d1117]"
                    : "border-[var(--border)] text-[var(--foreground)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                }`}
              >
                Contact us →
              </a>
            ) : tier.tier ? (
              <CheckoutButton
                tier={tier.tier}
                featured={tier.featured}
                label={`Subscribe to ${tier.name}`}
                loggedIn={loggedIn}
              />
            ) : null}
          </div>
        ))}
      </div>

      {/* Manage existing subscription */}
      <div className="border border-[var(--border)] rounded-xl px-6 py-4 flex items-center justify-between gap-4 bg-[var(--surface)]">
        <p className="text-sm text-[var(--muted)]">
          Already subscribed? Manage your plan, update payment, or cancel.
        </p>
        <ManageSubscriptionButton loggedIn={loggedIn} />
      </div>

      {/* FAQ */}
      <div className="flex flex-col gap-6 border-t border-[var(--border)] pt-10">
        <h2 className="text-lg font-bold">Common questions</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          {FAQ.map(({ q, a }) => (
            <div key={q}>
              <p className="text-sm font-semibold mb-1">{q}</p>
              <p className="text-sm text-[var(--muted)]">{a}</p>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}

const FAQ = [
  {
    q: "Will the free tier ever go away?",
    a: "No. The free public tier is a core commitment of cmdcheck — paste-and-analyze will always be free.",
  },
  {
    q: "What does 'private submission' mean?",
    a: "On free, commands are stored publicly and appear in search and recent feeds. On paid plans, your commands are stored privately and never appear in the public corpus.",
  },
  {
    q: "What are the beta enrichment features?",
    a: "Deep threat enrichment, YARA rule suggestions, and campaign correlation are in active development. Organization subscribers get early access as they roll out.",
  },
  {
    q: "Can I self-host instead?",
    a: "cmdcheck is open source. You can run your own instance with no limits. Paid plans are for teams who want a managed service with SLA and support.",
  },
  {
    q: "How does team billing work?",
    a: "One billing account per workspace. Members join via invite link. Subscribe on the pricing page and manage your plan from the Stripe customer portal.",
  },
  {
    q: "Is there a trial period?",
    a: "No trial period yet — the free tier gives you unlimited public analyses to evaluate the tool before subscribing.",
  },
];
