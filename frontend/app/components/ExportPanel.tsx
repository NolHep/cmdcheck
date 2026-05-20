"use client";

import { useState } from "react";
import type { AnalyzeResponse } from "@/app/lib/api";

function buildMarkdown(a: AnalyzeResponse): string {
  const lines: string[] = [];

  lines.push(`# ShellHawk Analysis — ${a.slug}`);
  lines.push("");

  if (a.command) {
    lines.push("## Command");
    lines.push("```");
    lines.push(a.command);
    lines.push("```");
    lines.push("");
  }

  if (a.threat_classes.length > 0) {
    lines.push("## Threat Behavior");
    for (const tc of a.threat_classes) {
      lines.push(`### ${tc.label} (${tc.confidence} confidence)`);
      for (const s of tc.signals) lines.push(`- ${s}`);
    }
    lines.push("");
  }

  const binaries = a.binaries_in_command?.length
    ? a.binaries_in_command
    : [
        ...(a.lolbas_matches ?? (a.lolbas_match ? [a.lolbas_match] : [])).map((m) => ({
          name: m.name ?? "", source: "lolbas" as const, description: m.description ?? null,
          abuse_note: null, functions: m.functions ?? [], techniques: m.technique_details ?? [], url: m.url ?? null,
        })),
        ...(a.gtfobins_matches ?? (a.gtfobins_match ? [a.gtfobins_match] : [])).map((m) => ({
          name: m.name, source: "gtfobins" as const, description: m.description ?? null,
          abuse_note: null, functions: m.functions, techniques: [], url: m.url,
        })),
      ];

  if (binaries.length > 0) {
    lines.push("## Binaries in Command");
    for (const b of binaries) {
      const badge = b.source === "lolbas" ? "LOLBAS" : b.source === "gtfobins" ? "GTFOBins" : "System binary";
      lines.push(`### ${b.name} [${badge}]`);
      if (b.description) lines.push(`- **Purpose**: ${b.description}`);
      if (b.abuse_note) lines.push(`- **Abuse pattern**: ${b.abuse_note}`);
      if (b.functions?.length) lines.push(`- **Abuse functions**: ${b.functions.join(", ")}`);
      if (b.techniques?.length) {
        const techs = b.techniques.map((t) => t.name ? `${t.id} (${t.name})` : t.id).join(", ");
        lines.push(`- **MITRE ATT&CK**: ${techs}`);
      }
      if (b.url) lines.push(`- **Reference**: ${b.url}`);
    }
    lines.push("");
  }

  if (a.loldrivers_match) {
    lines.push("## LOLDrivers Match (BYOVD)");
    lines.push(`- **Driver**: ${a.loldrivers_match.filename}`);
    if (a.loldrivers_match.category) lines.push(`- **Category**: ${a.loldrivers_match.category}`);
    lines.push("");
  }

  if (a.parent_verdict) {
    lines.push("## Parent Process Verdict");
    lines.push(`- **${a.parent_verdict.parent} → ${a.parent_verdict.child}**: ${a.parent_verdict.suspicion} suspicion`);
    lines.push(`- ${a.parent_verdict.explanation}`);
    lines.push("");
  }

  if (a.decoded_layers.length > 0) {
    lines.push(`## Decoded Payload (${a.decoded_layers.length} layer${a.decoded_layers.length !== 1 ? "s" : ""})`);
    const last = a.decoded_layers[a.decoded_layers.length - 1];
    lines.push(`**Encoding**: ${last.encoding}`);
    lines.push("```");
    lines.push(last.value.slice(0, 2000) + (last.value.length > 2000 ? "\n… (truncated)" : ""));
    lines.push("```");
    lines.push("");
  }

  if (a.vt_results.length > 0) {
    lines.push("## VirusTotal URL Scores");
    for (const vt of a.vt_results) {
      lines.push(`- **${vt.url}**: ${vt.malicious} malicious / ${vt.suspicious} suspicious / ${vt.total} engines`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push(`*Analyzed by ShellHawk — https://shellhawk.net/c/${a.slug}*`);

  return lines.join("\n");
}

function buildCsv(a: AnalyzeResponse): string {
  const escape = (v: string) => `"${v.replace(/"/g, '""')}"`;

  const threatClasses = a.threat_classes.map((tc) => `${tc.label} (${tc.confidence})`).join("; ");
  const techniques = [
    ...new Set(a.threat_classes.flatMap((tc) => tc.techniques.map((t) => t.id))),
  ].join("; ");
  const binaries = (a.binaries_in_command ?? []).map((b) => b.name).join("; ");
  const lolbas = (a.lolbas_matches ?? []).map((m) => m.name).join("; ");
  const decoded = a.decoded_layers.length > 0 ? a.decoded_layers[a.decoded_layers.length - 1].value.slice(0, 500) : "";
  const permalink = `https://shellhawk.net/c/${a.slug}`;

  const headers = ["slug", "command", "threat_classes", "techniques", "binaries", "lolbas_matches", "decoded_payload", "permalink"];
  const row = [a.slug, a.command ?? "", threatClasses, techniques, binaries, lolbas, decoded, permalink];

  return [headers.map(escape).join(","), row.map(escape).join(",")].join("\n");
}

export default function ExportPanel({ analysis }: { analysis: AnalyzeResponse }) {
  const [copied, setCopied] = useState(false);

  async function copyMarkdown() {
    await navigator.clipboard.writeText(buildMarkdown(analysis));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function downloadJson() {
    const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `shellhawk-${analysis.slug}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function downloadCsv() {
    const blob = new Blob([buildCsv(analysis)], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `shellhawk-${analysis.slug}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex items-center gap-3">
      <span className="text-[var(--muted)] text-xs">Export:</span>
      <button
        onClick={copyMarkdown}
        className="text-[var(--muted)] text-xs hover:text-[var(--foreground)] transition-colors"
      >
        {copied ? "Copied!" : "Copy as Markdown"}
      </button>
      <button
        onClick={downloadJson}
        className="text-[var(--muted)] text-xs hover:text-[var(--foreground)] transition-colors"
      >
        Download JSON
      </button>
      <button
        onClick={downloadCsv}
        className="text-[var(--muted)] text-xs hover:text-[var(--foreground)] transition-colors"
      >
        Download CSV
      </button>
    </div>
  );
}
