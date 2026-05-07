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

  return (
    <div className="max-w-4xl mx-auto w-full px-4 py-10 flex flex-col gap-8">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold font-mono text-[var(--accent)]">
            /c/{slug}
          </h1>
          <p className="text-[var(--muted)] text-sm mt-0.5">Command analysis</p>
        </div>
        <CopyLinkButton slug={slug} />
      </div>

      {/* Raw command */}
      {analysis.command && (
        <Section title="Command">
          <pre
            data-testid="command-display"
            className="font-mono text-sm bg-[var(--surface)] border border-[var(--border)] rounded-lg px-4 py-3 overflow-x-auto whitespace-pre-wrap break-all"
          >
            {analysis.command}
          </pre>
        </Section>
      )}

      {/* Decode layers */}
      {analysis.decoded_layers.length > 0 && (
        <Section title={`Decode layers (${analysis.decoded_layers.length})`}>
          <div className="flex flex-col gap-3">
            {analysis.decoded_layers.map((layer: DecodeLayer) => (
              <DecodeLayerBlock key={layer.layer} layer={layer} />
            ))}
          </div>
        </Section>
      )}

      {/* LOLBAS match */}
      <Section title="LOLBAS match">
        <LolbasCard match={analysis.lolbas_match} />
      </Section>

      {/* Parse tree */}
      {analysis.parsed !== null && (
        <Section title="Parse tree (bashlex AST)">
          <details className="group">
            <summary className="cursor-pointer text-[var(--muted)] text-sm hover:text-[var(--foreground)] list-none flex items-center gap-2">
              <span className="group-open:rotate-90 transition-transform inline-block">▶</span>
              Show raw AST
            </summary>
            <pre className="mt-3 font-mono text-xs bg-[var(--surface)] border border-[var(--border)] rounded-lg px-4 py-3 overflow-x-auto">
              {JSON.stringify(analysis.parsed, null, 2)}
            </pre>
          </details>
        </Section>
      )}

      {analysis.parsed_error && (
        <Section title="Parse error">
          <p className="text-[var(--danger)] font-mono text-sm">
            {analysis.parsed_error}
          </p>
        </Section>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-3">
      <h2 className="text-sm font-semibold text-[var(--muted)] uppercase tracking-wider">
        {title}
      </h2>
      {children}
    </div>
  );
}

function DecodeLayerBlock({ layer }: { layer: DecodeLayer }) {
  return (
    <details className="group border border-[var(--border)] rounded-lg overflow-hidden">
      <summary className="cursor-pointer flex items-center justify-between px-4 py-2.5 bg-[var(--surface)] hover:bg-[#1c2128] list-none">
        <div className="flex items-center gap-3">
          <span className="text-[var(--muted)] text-xs font-mono">Layer {layer.layer}</span>
          <span className="text-xs bg-[var(--border)] text-[var(--foreground)] px-2 py-0.5 rounded font-mono">
            {layer.encoding}
          </span>
        </div>
        <span className="text-[var(--muted)] text-xs group-open:rotate-180 transition-transform">▼</span>
      </summary>
      <pre className="font-mono text-xs px-4 py-3 overflow-x-auto whitespace-pre-wrap break-all bg-[var(--background)] text-[var(--foreground)]">
        {layer.value}
      </pre>
    </details>
  );
}

function LolbasCard({ match }: { match: LolbasMatch }) {
  if (!match) {
    return (
      <div className="border border-[var(--border)] rounded-lg px-4 py-3 text-[var(--muted)] text-sm">
        No LOLBAS match found.
      </div>
    );
  }

  return (
    <div className="border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="bg-[var(--surface)] px-4 py-3 flex items-start justify-between gap-4">
        <div>
          <span className="font-mono font-bold text-[var(--danger)]">{match.name}</span>
          {match.description && (
            <p className="text-[var(--muted)] text-sm mt-1">{match.description}</p>
          )}
        </div>
        {match.url && (
          <a
            href={match.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[var(--accent)] text-xs hover:underline shrink-0"
          >
            LOLBAS ↗
          </a>
        )}
      </div>
      {match.techniques.length > 0 && (
        <div className="px-4 py-3 flex flex-wrap gap-2">
          {match.techniques.map((t: string) => (
            <span
              key={t}
              className="text-xs bg-[var(--border)] text-[var(--foreground)] px-2 py-0.5 rounded font-mono"
            >
              {t}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
