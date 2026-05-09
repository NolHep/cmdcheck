import { notFound } from "next/navigation";
import { getAnalysis } from "@/app/lib/api";
import type { DecodeLayer, LolbasMatch } from "@/app/lib/api";
import CopyLinkButton from "@/app/components/CopyLinkButton";

export default async function AnalysisPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const analysis = await getAnalysis(slug);
  if (!analysis) notFound();

  const hasLolbas = analysis.lolbas_match !== null;
  const hasEncoding = analysis.decoded_layers.length > 0;
  const verdict = getVerdict(hasLolbas, hasEncoding);

  return (
    <div className="max-w-3xl mx-auto w-full px-4 py-8 flex flex-col gap-6">

      {/* Verdict banner */}
      <div className={`rounded-lg border px-4 py-3 flex items-start justify-between gap-4 ${verdict.style}`}>
        <div>
          <p className="font-bold text-sm uppercase tracking-wide">{verdict.label}</p>
          <p className="text-sm mt-0.5 opacity-80">{verdict.detail}</p>
        </div>
        <CopyLinkButton slug={slug} />
      </div>

      {/* Command */}
      {analysis.command && (
        <section>
          <h2 className="section-label">Command</h2>
          <pre className="code-block">{analysis.command}</pre>
        </section>
      )}

      {/* LOLBAS finding */}
      {hasLolbas && analysis.lolbas_match && (
        <section>
          <h2 className="section-label">Known-abused binary</h2>
          <LolbasCard match={analysis.lolbas_match} />
        </section>
      )}

      {/* Decode layers */}
      {hasEncoding && (
        <section>
          <h2 className="section-label">
            Encoded payload — {analysis.decoded_layers.length}{" "}
            {analysis.decoded_layers.length === 1 ? "layer" : "layers"} decoded
          </h2>
          <DecodeLayers layers={analysis.decoded_layers} />
        </section>
      )}

      {/* Parse error (only if bashlex failed — useful signal) */}
      {analysis.parsed_error && (
        <section>
          <h2 className="section-label">Parse note</h2>
          <p className="text-[var(--muted)] font-mono text-xs border border-[var(--border)] rounded-lg px-4 py-3">
            {analysis.parsed_error}
          </p>
        </section>
      )}

    </div>
  );
}

/* ── helpers ── */

function getVerdict(hasLolbas: boolean, hasEncoding: boolean) {
  if (hasLolbas && hasEncoding) {
    return {
      label: "Suspicious — encoded payload via known-abused binary",
      detail: "A LOLBAS binary was used to execute an encoded command. Common in living-off-the-land attacks.",
      style: "border-[var(--danger)] bg-[#2d1515] text-[var(--foreground)]",
    };
  }
  if (hasLolbas) {
    return {
      label: "Notable — known-abused binary detected",
      detail: "This binary appears in the LOLBAS catalog as commonly abused. No encoding detected.",
      style: "border-yellow-600 bg-[#2a2000] text-[var(--foreground)]",
    };
  }
  if (hasEncoding) {
    return {
      label: "Notable — encoded payload detected",
      detail: "The command contains encoded content that was decoded. Review the layers below.",
      style: "border-yellow-600 bg-[#2a2000] text-[var(--foreground)]",
    };
  }
  return {
    label: "Low signal",
    detail: "No known-abused binary or encoding detected. May still be malicious — use context.",
    style: "border-[var(--border)] bg-[var(--surface)] text-[var(--muted)]",
  };
}

function LolbasCard({ match }: { match: NonNullable<LolbasMatch> }) {
  return (
    <div className="border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="bg-[var(--surface)] px-4 py-3 flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono font-bold text-[var(--danger)]">{match.name}</span>
            {match.functions && match.functions.map((fn) => (
              <span key={fn} className="text-xs bg-[#3d1a1a] text-[var(--danger)] border border-[var(--danger)] border-opacity-30 px-2 py-0.5 rounded font-mono">
                {fn}
              </span>
            ))}
          </div>
          {match.description && (
            <p className="text-[var(--muted)] text-sm">{match.description}</p>
          )}
        </div>
        {match.url && (
          <a href={match.url} target="_blank" rel="noopener noreferrer"
            className="text-[var(--accent)] text-xs hover:underline shrink-0">
            LOLBAS ↗
          </a>
        )}
      </div>
      {match.techniques.length > 0 && (
        <div className="px-4 py-2.5 flex flex-wrap gap-2 border-t border-[var(--border)]">
          <span className="text-[var(--muted)] text-xs self-center">MITRE ATT&CK</span>
          {match.techniques.map((t) => (
            <a
              key={t}
              href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs bg-[var(--border)] hover:bg-[var(--accent)] hover:text-[#0d1117] text-[var(--foreground)] px-2 py-0.5 rounded font-mono transition-colors"
            >
              {t}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function DecodeLayers({ layers }: { layers: DecodeLayer[] }) {
  const last = layers[layers.length - 1];
  const intermediates = layers.slice(0, -1);

  return (
    <div className="flex flex-col gap-3">
      {/* Final decoded content — shown open */}
      <div className="border border-[var(--accent)] border-opacity-40 rounded-lg overflow-hidden">
        <div className="bg-[var(--surface)] px-4 py-2 flex items-center gap-3 border-b border-[var(--border)]">
          <span className="text-[var(--accent)] text-xs font-semibold uppercase tracking-wide">
            Final decoded content
          </span>
          <span className="text-xs bg-[var(--border)] text-[var(--muted)] px-2 py-0.5 rounded font-mono">
            {last.encoding}
          </span>
        </div>
        <pre className="font-mono text-xs px-4 py-3 overflow-x-auto whitespace-pre-wrap break-all">
          {last.value}
        </pre>
      </div>

      {/* Intermediate layers — collapsed */}
      {intermediates.length > 0 && (
        <details className="group">
          <summary className="cursor-pointer text-[var(--muted)] text-xs hover:text-[var(--foreground)] list-none flex items-center gap-1.5">
            <span className="group-open:rotate-90 transition-transform inline-block">▶</span>
            Show {intermediates.length} intermediate{" "}
            {intermediates.length === 1 ? "layer" : "layers"}
          </summary>
          <div className="mt-2 flex flex-col gap-2">
            {intermediates.map((layer) => (
              <div key={layer.layer} className="border border-[var(--border)] rounded-lg overflow-hidden">
                <div className="bg-[var(--surface)] px-4 py-2 flex items-center gap-3 border-b border-[var(--border)]">
                  <span className="text-[var(--muted)] text-xs font-mono">Layer {layer.layer}</span>
                  <span className="text-xs bg-[var(--border)] text-[var(--muted)] px-2 py-0.5 rounded font-mono">
                    {layer.encoding}
                  </span>
                </div>
                <pre className="font-mono text-xs px-4 py-3 overflow-x-auto whitespace-pre-wrap break-all">
                  {layer.value}
                </pre>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
