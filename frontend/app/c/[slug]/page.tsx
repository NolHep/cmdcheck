import type { Metadata } from "next";
import Link from "next/link";
import { cache } from "react";
import { notFound } from "next/navigation";
import { auth } from "@/auth";
import { getAnalysis } from "@/app/lib/api";

const getCachedAnalysis = cache(getAnalysis);
import type {
  AnalyzeResponse, DecodeLayer, LolbasMatch, GtfobinsMatch, LoldriversMatch,
  ThreatClass, ParentVerdict, TechniqueDetail, VtUrlResult, BinaryInCommand,
  ThreatIntelResult, ThreatActor,
} from "@/app/lib/api";
import CopyLinkButton from "@/app/components/CopyLinkButton";
import DeleteButton from "@/app/components/DeleteButton";
import ExportPanel from "@/app/components/ExportPanel";
import ReanalyzeForm from "@/app/components/ReanalyzeForm";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const analysis = await getCachedAnalysis(slug);
  if (!analysis || "deleted" in analysis) return { title: "Analysis — cmdcheck" };
  const a = analysis as AnalyzeResponse;
  const verdict = getVerdict(
    !!(a.lolbas_matches?.length || a.lolbas_match),
    !!(a.gtfobins_matches?.length || a.gtfobins_match),
    !!a.loldrivers_match,
    a.decoded_layers.length > 0,
    a.threat_classes,
  );
  const snippet = a.command ? a.command.slice(0, 120) : slug;
  const description = `${verdict.detail} | ${snippet}`;
  return {
    title: `${verdict.label} — cmdcheck`,
    description,
    openGraph: { title: `${verdict.label} — cmdcheck`, description, siteName: "cmdcheck", type: "website" },
    twitter: { card: "summary", title: `${verdict.label} — cmdcheck`, description },
  };
}

export default async function AnalysisPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const [analysis, session] = await Promise.all([getCachedAnalysis(slug), auth()]);
  if (!analysis) notFound();

  if ("deleted" in analysis && analysis.deleted) {
    return (
      <div className="max-w-3xl mx-auto w-full px-4 py-16 flex flex-col items-center gap-4 text-center">
        <p className="text-5xl text-[var(--border)]">—</p>
        <h2 className="text-xl font-bold">Analysis deleted</h2>
        <p className="text-[var(--muted)] text-sm max-w-sm">
          This command was removed by the submitter. The permalink no longer shows analysis data.
        </p>
        <Link href="/" className="text-[var(--accent)] text-sm hover:underline">
          Analyze a new command →
        </Link>
      </div>
    );
  }

  const a = analysis as AnalyzeResponse;
  const sessionEmail = session?.user?.email ?? null;
  const isAdmin = session?.user?.role === "admin";
  const canDelete =
    isAdmin ||
    (!!sessionEmail && !!a.submitter_email && sessionEmail === a.submitter_email);
  const lolbasMatches = a.lolbas_matches?.length ? a.lolbas_matches : (a.lolbas_match ? [a.lolbas_match] : []);
  const gtfobinsMatches = a.gtfobins_matches?.length ? a.gtfobins_matches : (a.gtfobins_match ? [a.gtfobins_match] : []);
  const hasLolbas = lolbasMatches.length > 0;
  const hasGtfobins = gtfobinsMatches.length > 0;
  const hasLoldrivers = !!a.loldrivers_match;
  const hasEncoding = a.decoded_layers.length > 0;
  const hasActors = a.attributed_actors && a.attributed_actors.length > 0;
  const verdict = getVerdict(hasLolbas, hasGtfobins, hasLoldrivers, hasEncoding, a.threat_classes);

  const hasSidebar =
    a.threat_classes.length > 0 ||
    (a.binaries_in_command && a.binaries_in_command.length > 0) ||
    hasLolbas || hasGtfobins ||
    !!a.parent_verdict ||
    hasActors;

  return (
    <div className="w-full max-w-[1400px] mx-auto px-4 py-8 flex flex-col gap-6">

      {/* Verdict banner — full width */}
      <div className={`rounded-xl border px-5 py-4 flex items-start justify-between gap-4 ${verdict.style}`}>
        <div className="min-w-0">
          <p className="font-semibold text-xs uppercase tracking-widest opacity-70 mb-1">{verdict.label}</p>
          <p className="text-sm leading-relaxed">{verdict.detail}</p>
        </div>
        <CopyLinkButton slug={slug} />
      </div>

      {/* Two-column grid — main content + sidebar */}
      <div className={`grid gap-6 ${hasSidebar ? "lg:grid-cols-3" : ""}`}>

        {/* ── Main column (2/3) ── */}
        <div className={`flex flex-col gap-6 ${hasSidebar ? "lg:col-span-2" : ""}`}>

          {/* Command */}
          {a.command && (
            <section>
              <h2 className="section-label">Command</h2>
              <pre className="code-block">{a.command}</pre>
              {a.redacted && (
                <p className="text-[var(--muted)] text-xs mt-1.5">
                  Sensitive data (credentials, internal IPs) was detected and masked before storage.
                </p>
              )}
            </section>
          )}

          {/* Story */}
          {a.story && (
            <section>
              <h2 className="section-label">Analysis</h2>
              <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface)] flex flex-col gap-3">
                {a.story.split("\n\n").map((para, i) => (
                  <p key={i} className="text-sm text-[var(--foreground)] leading-relaxed">{para}</p>
                ))}
              </div>
            </section>
          )}

          {/* LOLDrivers — in main col since it's critical */}
          {hasLoldrivers && a.loldrivers_match && (
            <section>
              <h2 className="section-label">Known-vulnerable driver (LOLDrivers)</h2>
              <LoldriversCard match={a.loldrivers_match} />
            </section>
          )}

          {/* Decode layers */}
          {hasEncoding && (
            <section>
              <h2 className="section-label">
                Encoded payload — {a.decoded_layers.length}{" "}
                {a.decoded_layers.length === 1 ? "layer" : "layers"} decoded
              </h2>
              <DecodeLayers layers={a.decoded_layers} />
            </section>
          )}

          {/* Threat intelligence */}
          {(a.threat_intel && a.threat_intel.length > 0) ? (
            <section>
              <h2 className="section-label">Indicators extracted from payload</h2>
              <ThreatIntelPanel results={a.threat_intel} configured={a.threat_intel_configured} />
            </section>
          ) : a.extracted_urls.length > 0 ? (
            <section>
              <h2 className="section-label">URLs extracted from payload</h2>
              <VtResultsCard urls={a.extracted_urls} results={a.vt_results} vtConfigured={a.vt_configured ?? false} />
            </section>
          ) : null}

          {/* Shell parser note */}
          {a.parsed_error && (
            <section>
              <h2 className="section-label">Shell parser</h2>
              <div className="border border-[var(--border)] rounded-lg px-4 py-3 flex flex-col gap-1.5">
                <p className="text-[var(--muted)] font-mono text-xs">{a.parsed_error}</p>
                <p className="text-[var(--muted)] text-xs italic">
                  This tool uses a Linux bash parser (bashlex). Windows commands, PowerShell, and
                  embedded scripts are expected to fail shell parsing — analysis above is not affected.
                </p>
              </div>
            </section>
          )}

          {/* Footer */}
          <div className="pt-4 border-t border-[var(--border)] flex flex-col gap-4">
            {a.command && <ReanalyzeForm command={a.command} slug={slug} />}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 flex-wrap">
              <ExportPanel analysis={a} />
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-[var(--muted)] text-xs">
                  {a.submitter_email
                    ? <><span className="opacity-60">by</span> {a.submitter_email}</>
                    : <span className="opacity-60">anonymous</span>}
                </span>
                <DeleteButton slug={slug} canDelete={canDelete} />
              </div>
            </div>
          </div>
        </div>

        {/* ── Sidebar (1/3) ── */}
        {hasSidebar && (
          <div className="flex flex-col gap-5">

            {/* Threat behavior */}
            {a.threat_classes.length > 0 && (
              <section>
                <h2 className="section-label">Threat behavior</h2>
                <ThreatBehavior classes={a.threat_classes} />
              </section>
            )}

            {/* Binaries in command */}
            {a.binaries_in_command && a.binaries_in_command.length > 0 ? (
              <section>
                <h2 className="section-label">
                  {a.binaries_in_command.length === 1 ? "Binary" : "Binaries"} in command
                </h2>
                <div className="flex flex-col gap-2">
                  {a.binaries_in_command.map((b) => (
                    <BinaryInCommandCard key={b.name} binary={b} />
                  ))}
                </div>
              </section>
            ) : (hasLolbas || hasGtfobins) ? (
              <section>
                <h2 className="section-label">Known-abused binaries</h2>
                <div className="flex flex-col gap-2">
                  {lolbasMatches.map((m) => <LolbasCard key={m.name ?? "lolbas"} match={m} />)}
                  {gtfobinsMatches.map((m) => <GtfobinsCard key={m.name} match={m} />)}
                </div>
              </section>
            ) : null}

            {/* Parent process */}
            {a.parent_verdict && (
              <section>
                <h2 className="section-label">Parent process</h2>
                <ParentVerdictCard verdict={a.parent_verdict} />
              </section>
            )}

            {/* Threat actor attribution */}
            {hasActors && (
              <section>
                <h2 className="section-label">Threat actor attribution</h2>
                <ThreatActorsCard actors={a.attributed_actors} />
              </section>
            )}

          </div>
        )}
      </div>
    </div>
  );
}

/* ── verdict ── */

function getVerdict(
  hasLolbas: boolean, hasGtfobins: boolean, hasLoldrivers: boolean,
  hasEncoding: boolean, threatClasses: ThreatClass[] = [],
) {
  const hasBinary = hasLolbas || hasGtfobins;
  const highClasses = threatClasses.filter((tc) => tc.confidence === "high");
  const mediumClasses = threatClasses.filter((tc) => tc.confidence === "medium");

  if (hasLoldrivers) return {
    label: "Suspicious — known-vulnerable driver (BYOVD)",
    detail: "A Bring-Your-Own-Vulnerable-Driver attack pattern was detected. This is a kernel-level privilege escalation technique.",
    style: "border-[var(--danger)] bg-[#2d1515] text-[var(--foreground)]",
  };
  if (hasBinary && hasEncoding) return {
    label: "Suspicious — encoded payload via known-abused binary",
    detail: "A LOLbin was used to execute an encoded command. Common in living-off-the-land attacks.",
    style: "border-[var(--danger)] bg-[#2d1515] text-[var(--foreground)]",
  };
  if (highClasses.length > 0) return {
    label: "Suspicious — high-confidence threat behavior",
    detail: `High-confidence signals: ${highClasses.map((tc) => tc.label).join(", ")}.`,
    style: "border-[var(--danger)] bg-[#2d1515] text-[var(--foreground)]",
  };
  if (hasBinary) return {
    label: "Notable — known-abused binary detected",
    detail: "This binary appears in the LOLBAS/GTFOBins catalog as commonly abused. No encoding detected.",
    style: "border-yellow-600 bg-[#2a2000] text-[var(--foreground)]",
  };
  if (hasEncoding) return {
    label: "Notable — encoded payload detected",
    detail: "The command contains encoded content that was decoded. Review the layers below.",
    style: "border-yellow-600 bg-[#2a2000] text-[var(--foreground)]",
  };
  if (mediumClasses.length > 0) return {
    label: "Notable — threat behavior detected",
    detail: `Medium-confidence signals: ${mediumClasses.map((tc) => tc.label).join(", ")}.`,
    style: "border-yellow-600 bg-[#2a2000] text-[var(--foreground)]",
  };
  if (threatClasses.length > 0) return {
    label: "Low signal — weak indicators present",
    detail: "Low-confidence threat signals were identified. May be benign — use context.",
    style: "border-[var(--border)] bg-[var(--surface)] text-[var(--muted)]",
  };
  return {
    label: "Low signal",
    detail: "No known-abused binary or encoding detected. May still be malicious — use context.",
    style: "border-[var(--border)] bg-[var(--surface)] text-[var(--muted)]",
  };
}

/* ── threat behavior ── */

const CONF_STYLE: Record<string, string> = {
  high: "border-[var(--danger)] text-[var(--danger)] bg-[#3d1a1a]",
  medium: "border-yellow-600 text-yellow-400 bg-[#2a1e00]",
  low: "border-[var(--border)] text-[var(--muted)] bg-transparent",
};

function ThreatBehavior({ classes }: { classes: ThreatClass[] }) {
  return (
    <div className="flex flex-col gap-2">
      {classes.map((tc) => (
        <div key={tc.name} className="border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-3 py-2 flex items-center gap-2 border-b border-[var(--border)] bg-[var(--surface)]">
            <span className={`text-xs font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${CONF_STYLE[tc.confidence]}`}>
              {tc.confidence}
            </span>
            <span className="font-semibold text-xs text-[var(--foreground)]">{tc.label}</span>
          </div>
          <ul className="px-3 py-2 flex flex-col gap-1">
            {tc.signals.map((s) => (
              <li key={s} className="text-[var(--muted)] text-xs flex items-start gap-1.5">
                <span className="mt-0.5 shrink-0 text-[var(--border)]">›</span>
                {s}
              </li>
            ))}
          </ul>
          {tc.techniques && tc.techniques.length > 0 && (
            <div className="px-3 py-2 border-t border-[var(--border)] flex flex-wrap gap-1.5">
              {tc.techniques.map((t) => (
                <a key={t.id}
                  href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}`}
                  target="_blank" rel="noopener noreferrer"
                  className="group flex items-center gap-1 bg-[var(--border)] hover:bg-[var(--surface)] border border-transparent hover:border-[var(--accent)] rounded px-1.5 py-0.5 transition-colors"
                >
                  <span className="font-mono text-xs text-[var(--foreground)]">{t.id}</span>
                  {t.name && <span className="text-xs text-[var(--muted)] group-hover:text-[var(--foreground)] hidden xl:inline">— {t.name}</span>}
                </a>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ── parent verdict ── */

const SUSPICION_STYLE: Record<string, string> = {
  high: "border-[var(--danger)] bg-[#2d1515]",
  medium: "border-yellow-600 bg-[#2a2000]",
  low: "border-[var(--border)] bg-[var(--surface)]",
  benign: "border-[var(--success)] bg-[#0d2115]",
};
const SUSPICION_LABEL: Record<string, string> = {
  high: "High suspicion", medium: "Medium suspicion", low: "Low suspicion", benign: "Benign",
};

function ParentVerdictCard({ verdict }: { verdict: NonNullable<ParentVerdict> }) {
  return (
    <div className={`border rounded-lg px-3 py-3 ${SUSPICION_STYLE[verdict.suspicion]}`}>
      <div className="flex items-center gap-2 mb-1.5 flex-wrap">
        <span className="font-mono text-xs text-[var(--muted)]">{verdict.parent}</span>
        <span className="text-[var(--border)] text-xs">→</span>
        <span className="font-mono text-xs font-bold text-[var(--foreground)]">{verdict.child}</span>
        <span className="ml-auto text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
          {SUSPICION_LABEL[verdict.suspicion]}
        </span>
      </div>
      <p className="text-xs text-[var(--muted)]">{verdict.explanation}</p>
    </div>
  );
}

/* ── threat actor attribution ── */

const ACTOR_CONF_STYLE: Record<string, string> = {
  high: "border-[var(--danger)] text-[var(--danger)] bg-[#3d1a1a]",
  medium: "border-yellow-600 text-yellow-400 bg-[#2a1e00]",
  low: "border-[var(--border)] text-[var(--muted)] bg-transparent",
};
const COUNTRY_FLAG: Record<string, string> = {
  Russia: "🇷🇺", China: "🇨🇳", "North Korea": "🇰🇵", Iran: "🇮🇷",
  Vietnam: "🇻🇳", Nigeria: "🇳🇬", Multiple: "🌐", Unknown: "❓",
};

function ThreatActorsCard({ actors }: { actors: ThreatActor[] }) {
  return (
    <div className="border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="flex flex-col divide-y divide-[var(--border)]">
        {actors.map((actor) => (
          <div key={actor.id} className="px-3 py-3 flex flex-col gap-1.5">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-1.5 flex-wrap min-w-0">
                <span className="text-sm">{COUNTRY_FLAG[actor.country] ?? "❓"}</span>
                <a
                  href={actor.url}
                  target="_blank" rel="noopener noreferrer"
                  className="font-semibold text-sm text-[var(--accent)] hover:underline"
                >
                  {actor.name}
                </a>
                {actor.aliases.length > 0 && (
                  <span className="text-xs text-[var(--muted)] truncate">
                    ({actor.aliases.slice(0, 2).join(", ")})
                  </span>
                )}
              </div>
              <span className={`shrink-0 text-xs font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${ACTOR_CONF_STYLE[actor.confidence]}`}>
                {actor.confidence}
              </span>
            </div>
            <p className="text-xs text-[var(--muted)] leading-relaxed line-clamp-2">{actor.description}</p>
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-xs text-[var(--muted)]">{actor.overlap_count} matched:</span>
              {actor.matched_techniques.map((tid) => (
                <a key={tid}
                  href={`https://attack.mitre.org/techniques/${tid.replace(".", "/")}`}
                  target="_blank" rel="noopener noreferrer"
                  className="font-mono text-xs bg-[var(--border)] hover:bg-[var(--surface)] border border-transparent hover:border-[var(--accent)] rounded px-1.5 py-0.5 transition-colors text-[var(--foreground)]"
                >
                  {tid}
                </a>
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="px-3 py-2 border-t border-[var(--border)] bg-[var(--surface)]">
        <p className="text-xs text-[var(--muted)]">
          Attribution based on MITRE ATT&amp;CK technique overlap. Confidence reflects TTP match depth — not a definitive attribution.
        </p>
      </div>
    </div>
  );
}

/* ── LOLBAS card ── */

function LolbasCard({ match }: { match: NonNullable<LolbasMatch> }) {
  return (
    <div className="border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="bg-[var(--surface)] px-3 py-2 flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono font-bold text-sm text-[var(--danger)]">{match.name}</span>
            {match.functions && match.functions.map((fn) => (
              <span key={fn} className="text-xs bg-[#3d1a1a] text-[var(--danger)] border border-[var(--danger)] border-opacity-30 px-1.5 py-0.5 rounded font-mono">
                {fn}
              </span>
            ))}
          </div>
          {match.description && <p className="text-[var(--muted)] text-xs">{match.description}</p>}
        </div>
        {match.url && (
          <a href={match.url} target="_blank" rel="noopener noreferrer"
            className="text-[var(--accent)] text-xs hover:underline shrink-0">↗</a>
        )}
      </div>
      {match.techniques.length > 0 && (
        <div className="px-3 py-2 flex flex-wrap gap-1.5 border-t border-[var(--border)]">
          {(match.technique_details ?? match.techniques.map((id) => ({ id, name: null, tactic: null }))).map(
            (t: TechniqueDetail) => (
              <a key={t.id}
                href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}`}
                target="_blank" rel="noopener noreferrer"
                className="font-mono text-xs bg-[var(--border)] hover:bg-[var(--surface)] border border-transparent hover:border-[var(--accent)] rounded px-1.5 py-0.5 transition-colors text-[var(--foreground)]"
              >
                {t.id}
              </a>
            )
          )}
        </div>
      )}
    </div>
  );
}

/* ── GTFOBins card ── */

const GTFO_FN_STYLE: Record<string, string> = {
  shell: "bg-[#3d1a1a] text-[var(--danger)] border-[var(--danger)]",
  sudo: "bg-[#3d1a1a] text-[var(--danger)] border-[var(--danger)]",
  suid: "bg-[#3d1a1a] text-[var(--danger)] border-[var(--danger)]",
  "file-write": "bg-[#2a1e00] text-yellow-400 border-yellow-600",
  "file-read": "bg-[#2a1e00] text-yellow-400 border-yellow-600",
  "file-upload": "bg-[#2a1e00] text-yellow-400 border-yellow-600",
  "file-download": "bg-[#2a1e00] text-yellow-400 border-yellow-600",
};

function GtfobinsCard({ match }: { match: NonNullable<GtfobinsMatch> }) {
  return (
    <div className="border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="bg-[var(--surface)] px-3 py-2 flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono font-bold text-sm text-[var(--danger)]">{match.name}</span>
            {match.functions.map((fn) => (
              <span key={fn} className={`text-xs border border-opacity-40 px-1.5 py-0.5 rounded font-mono ${GTFO_FN_STYLE[fn] ?? "bg-[var(--border)] text-[var(--muted)] border-[var(--border)]"}`}>
                {fn}
              </span>
            ))}
          </div>
          {match.description && <p className="text-[var(--muted)] text-xs">{match.description}</p>}
        </div>
        <a href={match.url} target="_blank" rel="noopener noreferrer"
          className="text-[var(--accent)] text-xs hover:underline shrink-0">↗</a>
      </div>
    </div>
  );
}

/* ── unified binary-in-command card ── */

const SOURCE_BADGE: Record<BinaryInCommand["source"], { label: string; style: string }> = {
  lolbas:      { label: "LOLBAS",         style: "bg-[#3d1a1a] text-[var(--danger)] border-[var(--danger)]" },
  gtfobins:    { label: "GTFOBins",       style: "bg-[#3d1a1a] text-[var(--danger)] border-[var(--danger)]" },
  system:      { label: "System binary",  style: "bg-[#2a1e00] text-yellow-400 border-yellow-600" },
  threat_tool: { label: "Attack tool",    style: "bg-[#3d1a1a] text-[var(--danger)] border-[var(--danger)]" },
  unknown:     { label: "Unknown",        style: "bg-[var(--surface)] text-[var(--muted)] border-[var(--border)]" },
};

function BinaryInCommandCard({ binary }: { binary: BinaryInCommand }) {
  const badge = SOURCE_BADGE[binary.source];
  const isDangerous = binary.source === "lolbas" || binary.source === "gtfobins" || binary.source === "threat_tool";

  return (
    <div className="border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="bg-[var(--surface)] px-3 py-2 flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`font-mono font-bold text-sm ${isDangerous ? "text-[var(--danger)]" : "text-[var(--foreground)]"}`}>
              {binary.name}
            </span>
            <span className={`text-xs border border-opacity-40 px-1.5 py-0.5 rounded font-mono shrink-0 ${badge.style}`}>
              {badge.label}
            </span>
            {binary.functions && binary.functions.map((fn) => (
              <span key={fn} className="text-xs bg-[var(--border)] text-[var(--muted)] px-1.5 py-0.5 rounded font-mono">
                {fn}
              </span>
            ))}
          </div>
          {binary.description && <p className="text-[var(--muted)] text-xs">{binary.description}</p>}
          {binary.abuse_note && (
            <p className="text-xs text-yellow-400 border-l-2 border-yellow-600 pl-2">{binary.abuse_note}</p>
          )}
        </div>
        {binary.url && (
          <a href={binary.url} target="_blank" rel="noopener noreferrer"
            className="text-[var(--accent)] text-xs hover:underline shrink-0">↗</a>
        )}
      </div>
      {binary.techniques && binary.techniques.length > 0 && (
        <div className="px-3 py-2 border-t border-[var(--border)] flex flex-wrap gap-1.5">
          {binary.techniques.map((t) => (
            <a key={t.id}
              href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}`}
              target="_blank" rel="noopener noreferrer"
              className="font-mono text-xs bg-[var(--border)] hover:bg-[var(--surface)] border border-transparent hover:border-[var(--accent)] rounded px-1.5 py-0.5 transition-colors text-[var(--foreground)]"
            >
              {t.id}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── LOLDrivers card ── */

function LoldriversCard({ match }: { match: NonNullable<LoldriversMatch> }) {
  return (
    <div className="border border-[var(--danger)] bg-[#2d1515] rounded-lg overflow-hidden">
      <div className="px-4 py-3 flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1.5">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono font-bold text-[var(--danger)]">{match.filename}</span>
            {match.category && (
              <span className="text-xs bg-[#3d1a1a] text-[var(--danger)] border border-[var(--danger)] border-opacity-30 px-2 py-0.5 rounded font-mono">
                {match.category}
              </span>
            )}
          </div>
          <p className="text-[var(--muted)] text-sm">
            This driver is catalogued as known-vulnerable and is used in BYOVD attacks to disable
            security products or escalate privileges at the kernel level.
          </p>
          {match.resources && match.resources.length > 0 && (
            <div className="flex gap-2 flex-wrap mt-0.5">
              {match.resources.map((url, i) => (
                <a key={url} href={url} target="_blank" rel="noopener noreferrer"
                  className="text-[var(--accent)] text-xs hover:underline">
                  Reference {i + 1} ↗
                </a>
              ))}
            </div>
          )}
        </div>
        <a href="https://www.loldrivers.io/" target="_blank" rel="noopener noreferrer"
          className="text-[var(--accent)] text-xs hover:underline shrink-0">LOLDrivers ↗</a>
      </div>
    </div>
  );
}

/* ── threat intelligence panel ── */

function SourceBadge({ label, value, danger }: { label: string; value: string; danger?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border font-mono ${
      danger
        ? "bg-[#3d1a1a] text-[var(--danger)] border-[var(--danger)] border-opacity-50"
        : "bg-[var(--surface)] text-[var(--muted)] border-[var(--border)]"
    }`}>
      <span className="text-[var(--muted)] font-sans not-italic">{label}</span>
      {value}
    </span>
  );
}

function ThreatIntelPanel({
  results, configured,
}: {
  results: ThreatIntelResult[];
  configured?: { abuseipdb: boolean; otx: boolean };
}) {
  const allClean = results.every((r) => {
    const vt = r.virustotal; const ub = r.urlhaus; const tf = r.threatfox;
    const gn = r.greynoise; const ab = r.abuseipdb;
    return (!vt || vt.malicious === 0) && (!ub || ub.status === "offline" || ub.status === "unknown") &&
      !tf && (!gn || gn.classification === "unknown" || gn.riot) && (!ab || ab.score < 25);
  });

  return (
    <div className="border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="flex flex-col divide-y divide-[var(--border)]">
        {results.map((r) => {
          const isDangerous =
            (r.virustotal && r.virustotal.malicious > 0) ||
            (r.urlhaus && r.urlhaus.status === "online") || !!r.threatfox ||
            (r.greynoise && r.greynoise.classification === "malicious") ||
            (r.abuseipdb && r.abuseipdb.score >= 50);

          return (
            <div key={r.indicator} className={`px-4 py-3 flex flex-col gap-2 ${isDangerous ? "bg-[#1a0d0d]" : ""}`}>
              <div className="flex items-start gap-3 flex-wrap">
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`text-xs font-mono px-1.5 py-0.5 rounded border ${
                    r.type === "ip"
                      ? "border-yellow-600 text-yellow-400 bg-[#2a1e00]"
                      : "border-[var(--border)] text-[var(--muted)] bg-[var(--surface)]"
                  }`}>{r.type === "ip" ? "IP" : "URL"}</span>
                  <span className="font-mono text-xs text-[var(--foreground)] break-all">{r.indicator}</span>
                </div>
                <div className="flex gap-1.5 flex-wrap ml-auto shrink-0">
                  {r.virustotal && (
                    <SourceBadge label="VT " value={r.virustotal.malicious > 0 ? `${r.virustotal.malicious}/${r.virustotal.total} malicious` : `clean (${r.virustotal.total})`} danger={r.virustotal.malicious > 0} />
                  )}
                  {r.urlhaus && <SourceBadge label="URLhaus " value={r.urlhaus.status} danger={r.urlhaus.status === "online"} />}
                  {r.threatfox && <SourceBadge label="ThreatFox " value={`${r.threatfox.malware ?? r.threatfox.threat_type ?? "IOC"} (${r.threatfox.confidence ?? "?"}%)`} danger />}
                  {r.greynoise && <SourceBadge label="GreyNoise " value={r.greynoise.riot ? "known-good" : r.greynoise.classification} danger={r.greynoise.classification === "malicious"} />}
                  {r.abuseipdb && <SourceBadge label="AbuseIPDB " value={`${r.abuseipdb.score}% abuse`} danger={r.abuseipdb.score >= 50} />}
                  {r.otx && r.otx.pulses > 0 && <SourceBadge label="OTX " value={`${r.otx.pulses} pulse${r.otx.pulses !== 1 ? "s" : ""}`} danger={r.otx.pulses >= 3} />}
                  {!r.virustotal && !r.urlhaus && !r.threatfox && !r.greynoise && !r.abuseipdb && !r.otx && (
                    <span className="text-xs text-[var(--muted)]">no results</span>
                  )}
                </div>
              </div>
              {r.urlhaus?.tags && r.urlhaus.tags.length > 0 && (
                <div className="flex gap-1 flex-wrap">
                  {r.urlhaus.tags.map((t) => (
                    <span key={t} className="text-xs bg-[var(--border)] text-[var(--muted)] px-1.5 py-0.5 rounded">{t}</span>
                  ))}
                </div>
              )}
              {r.otx?.malware_families && r.otx.malware_families.length > 0 && (
                <div className="flex gap-1 flex-wrap">
                  {r.otx.malware_families.map((m) => (
                    <span key={m} className="text-xs bg-[#2a1e00] text-yellow-400 border border-yellow-600 border-opacity-40 px-1.5 py-0.5 rounded">{m}</span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div className="px-4 py-2 border-t border-[var(--border)] bg-[var(--surface)] flex items-center justify-between gap-4 flex-wrap">
        <p className="text-xs text-[var(--muted)]">
          {allClean ? "All indicators appear clean across queried sources." : "Malicious indicators detected — review above."}
        </p>
        <div className="flex gap-2 flex-wrap">
          {["URLhaus", "ThreatFox", "GreyNoise"].map((s) => (
            <span key={s} className="text-xs text-[var(--success)]">{s} ✓</span>
          ))}
          {configured?.abuseipdb
            ? <span className="text-xs text-[var(--success)]">AbuseIPDB ✓</span>
            : <span className="text-xs text-[var(--muted)]">AbuseIPDB (no key)</span>}
          {configured?.otx
            ? <span className="text-xs text-[var(--success)]">OTX ✓</span>
            : <span className="text-xs text-[var(--muted)]">OTX (no key)</span>}
        </div>
      </div>
    </div>
  );
}

/* ── VirusTotal URL results ── */

function VtResultsCard({ urls, results, vtConfigured }: { urls: string[]; results: VtUrlResult[]; vtConfigured: boolean }) {
  const byUrl = new Map(results.map((r) => [r.url, r]));
  return (
    <div className="border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="flex flex-col divide-y divide-[var(--border)]">
        {urls.map((url) => {
          const vt = byUrl.get(url);
          return (
            <div key={url} className="px-4 py-2.5 flex items-center gap-3 flex-wrap">
              <span className="font-mono text-xs text-[var(--foreground)] break-all flex-1 min-w-0">{url}</span>
              {vt ? (
                <span className={`text-xs font-semibold px-2 py-0.5 rounded border shrink-0 ${
                  vt.malicious > 0 ? "bg-[#3d1a1a] text-[var(--danger)] border-[var(--danger)] border-opacity-40"
                    : vt.suspicious > 0 ? "bg-[#2a1e00] text-yellow-400 border-yellow-600"
                    : "bg-[var(--surface)] text-[var(--muted)] border-[var(--border)]"
                }`}>
                  {vt.malicious > 0 ? `${vt.malicious}/${vt.total} malicious`
                    : vt.suspicious > 0 ? `${vt.suspicious}/${vt.total} suspicious`
                    : `clean (${vt.total} engines)`}
                </span>
              ) : (
                <span className="text-xs text-[var(--muted)] shrink-0">
                  {vtConfigured ? "not in VirusTotal" : "VT lookup not configured"}
                </span>
              )}
            </div>
          );
        })}
      </div>
      <div className="px-4 py-2 border-t border-[var(--border)] bg-[var(--surface)]">
        <p className="text-xs text-[var(--muted)]">
          {vtConfigured ? "URLs looked up in VirusTotal (read-only — no data submitted)." : "Set VIRUSTOTAL_API_KEY on the backend to enable reputation lookups."}
        </p>
      </div>
    </div>
  );
}

/* ── decode layers ── */

function DecodeLayers({ layers }: { layers: DecodeLayer[] }) {
  const last = layers[layers.length - 1];
  const intermediates = layers.slice(0, -1);

  return (
    <div className="flex flex-col gap-3">
      <div className="border border-[var(--accent)] border-opacity-40 rounded-lg overflow-hidden">
        <div className="bg-[var(--surface)] px-4 py-2 flex items-center gap-3 border-b border-[var(--border)]">
          <span className="text-[var(--accent)] text-xs font-semibold uppercase tracking-wide">Final decoded content</span>
          <span className="text-xs bg-[var(--border)] text-[var(--muted)] px-2 py-0.5 rounded font-mono">{last.encoding}</span>
        </div>
        <pre className="font-mono text-xs px-4 py-3 whitespace-pre-wrap break-all">{last.value}</pre>
      </div>
      {intermediates.length > 0 && (
        <details className="group">
          <summary className="cursor-pointer text-[var(--muted)] text-xs hover:text-[var(--foreground)] list-none flex items-center gap-1.5">
            <span className="group-open:rotate-90 transition-transform inline-block">▶</span>
            Show {intermediates.length} intermediate {intermediates.length === 1 ? "layer" : "layers"}
          </summary>
          <div className="mt-2 flex flex-col gap-2">
            {intermediates.map((layer) => (
              <div key={layer.layer} className="border border-[var(--border)] rounded-lg overflow-hidden">
                <div className="bg-[var(--surface)] px-4 py-2 flex items-center gap-3 border-b border-[var(--border)]">
                  <span className="text-[var(--muted)] text-xs font-mono">Layer {layer.layer}</span>
                  <span className="text-xs bg-[var(--border)] text-[var(--muted)] px-2 py-0.5 rounded font-mono">{layer.encoding}</span>
                </div>
                <pre className="font-mono text-xs px-4 py-3 whitespace-pre-wrap break-all">{layer.value}</pre>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
