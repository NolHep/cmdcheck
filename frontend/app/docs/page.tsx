import Link from "next/link";

export const metadata = {
  title: "Documentation — ShellHawk",
  description: "How ShellHawk works, what it analyzes, and how we handle your data.",
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-bold text-[var(--foreground)] border-b border-[var(--border)] pb-2">{title}</h2>
      {children}
    </section>
  );
}

function P({ children }: { children: React.ReactNode }) {
  return <p className="text-[var(--muted)] text-sm leading-relaxed">{children}</p>;
}

function Tag({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-block bg-[var(--surface)] border border-[var(--border)] rounded px-1.5 py-0.5 font-mono text-xs text-[var(--foreground)]">
      {children}
    </span>
  );
}

export default function DocsPage() {
  return (
    <div className="max-w-3xl mx-auto w-full px-4 py-10 flex flex-col gap-10">
      <div>
        <h1 className="text-3xl font-bold mb-2">Documentation</h1>
        <p className="text-[var(--muted)] text-sm">
          ShellHawk is a free command-line analyzer for incident responders.
          Paste a suspicious command, get a structured analysis and a shareable permalink.
        </p>
      </div>

      <Section title="What it does">
        <P>
          ShellHawk analyzes command-line strings and returns a structured verdict covering:
          obfuscation decoding (base64, UTF-16LE, gzip — up to 5 layers), LOLBAS/GTFOBins binary
          matching, MITRE ATT&amp;CK technique tagging, LOLDrivers (BYOVD) detection, parent process
          plausibility scoring, and threat class classification.
        </P>
        <P>
          Every analysis produces a stable permalink at <Tag>/c/&lt;slug&gt;</Tag>. The slug is a
          base32-encoded SHA-256 of the normalized command, so the same command always resolves to
          the same URL — submissions are idempotent.
        </P>
      </Section>

      <Section title="What it is NOT">
        <ul className="flex flex-col gap-2">
          {[
            "A SIEM, SOAR, or EDR. It does not ingest your logs.",
            "A generic shell explainer — explainshell.com serves Linux learners; we serve incident responders looking at hostile commands.",
            "A CyberChef replacement — CyberChef lets you build manual recipes; ShellHawk is paste-and-go with a security verdict.",
            "A URL scanner — urlscan.io does that. ShellHawk enriches URLs found inside decoded payloads, but URL scanning is not its primary purpose.",
            "A file sandbox — ANY.RUN does that. Paste the command you extracted; don't expect file execution.",
          ].map((item) => (
            <li key={item} className="text-[var(--muted)] text-sm flex gap-2">
              <span className="text-[var(--border)] shrink-0">—</span>
              {item}
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Analysis pipeline">
        <div className="flex flex-col gap-2">
          {[
            ["1. Parse", "bashlex parses the shell AST. Windows commands and PowerShell are expected to fail the Linux parser — this does not affect the analysis."],
            ["2. Decode", "Recursive decoding of base64 → UTF-16LE → gzip → repeat, up to 5 layers. Stops at 'complex obfuscation, manual review needed' beyond that."],
            ["3. LOLBAS / GTFOBins", "Binary-name match against vendored LOLBAS and GTFOBins catalogs, then an argument-similarity score (SequenceMatcher + flag-set Jaccard) against each entry's known abuse examples — distinguishes abuse patterns from benign dual-use."],
            ["4. LOLDrivers", "Filename matching against loldrivers.io catalog — flags Bring-Your-Own-Vulnerable-Driver patterns."],
            ["5. MITRE ATT&CK", "Technique IDs from LOLBAS matches are enriched with names, tactics, and links from the official STIX dataset."],
            ["6. Threat classification", "7 threat classes (dropper, loader, C2/persistence, credential theft, lateral movement, defense evasion, recon) via regex signal rules with high/medium/low confidence."],
            ["7. Parent process", "Suspicion score for the parent→child process pair against known-bad relationships (e.g. winword.exe → powershell.exe = high)."],
            ["8. VirusTotal", "URLs extracted from decoded layers are looked up in VirusTotal (read-only — no data submitted). Requires VIRUSTOTAL_API_KEY."],
          ].map(([step, desc]) => (
            <div key={step} className="flex gap-3">
              <span className="text-[var(--accent)] text-xs font-semibold shrink-0 w-36">{step}</span>
              <span className="text-[var(--muted)] text-sm">{desc}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Privacy">
        <P>
          ShellHawk is built for analysts who paste real commands from real incidents. Privacy is
          non-negotiable.
        </P>
        <ul className="flex flex-col gap-2 mt-1">
          {[
            "Commands are redacted before storage — credentials, internal IPs, and NTLM hashes are masked.",
            "No third-party analytics scripts. No Google Analytics, Hotjar, or Segment.",
            "VirusTotal enrichment is read-only. We look up URLs VT already knows about; we never submit novel URLs.",
            "You can delete your submission at any time. The slug becomes a tombstone — old links show 'deleted', not a broken 404.",
            "Public commands are stored in a shared corpus and may appear in search results. If this is a concern, delete after analysis.",
          ].map((item) => (
            <li key={item} className="text-[var(--muted)] text-sm flex gap-2">
              <span className="text-[var(--success)] shrink-0">✓</span>
              {item}
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Data sources">
        <div className="flex flex-col gap-2">
          {[
            ["LOLBAS", "LOLBAS-Project/LOLBAS", "https://lolbas-project.github.io/", "Vendored as a git submodule, refreshed weekly."],
            ["GTFOBins", "GTFOBins/GTFOBins.github.io", "https://gtfobins.github.io/", "Vendored as a git submodule, refreshed weekly."],
            ["LOLDrivers", "loldrivers.io", "https://www.loldrivers.io/", "Fetched via API and baked into build, refreshed weekly."],
            ["MITRE ATT&CK", "mitre/cti", "https://attack.mitre.org/", "Enterprise STIX bundle, pinned version, refreshed quarterly."],
          ].map(([name, repo, url, note]) => (
            <div key={name} className="flex items-start gap-3 py-2 border-b border-[var(--border)] last:border-0">
              <div className="w-28 shrink-0">
                <span className="text-sm font-semibold text-[var(--foreground)]">{name}</span>
              </div>
              <div>
                <a href={url} target="_blank" rel="noopener noreferrer" className="text-[var(--accent)] text-sm hover:underline">
                  {repo} ↗
                </a>
                <p className="text-xs text-[var(--muted)] mt-0.5">{note}</p>
              </div>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Open source & feedback">
        <P>
          Found a bug or have a feature request?{" "}
          <Link href="/feedback" className="text-[var(--accent)] hover:underline">
            Submit a bug report
          </Link>
          . No account required.
        </P>
      </Section>
    </div>
  );
}
