# CLAUDE.md

Working name: **cmdcheck** (rename freely; placeholder).

## What this is

A free web tool where SOC analysts paste a suspicious command line and get back a structured analysis: deobfuscation, LOLBAS abuse pattern match, MITRE ATT&CK technique mapping, parent-process plausibility, and threat-class identification. Every analysis produces a shareable permalink. Modeled after ANY.RUN and ransomware.live: free public tier as the funnel, paid team/API tier later.

## What this is not

- Not a SIEM, not a SOAR, not an EDR. It does not ingest tenant logs.
- Not tenant-specific. It does not need access to anyone's environment to be useful.
- Not a generic shell explainer. explainshell.com already serves Linux learners. Our audience is incident responders looking at hostile commands.
- Not a CyberChef replacement. CyberChef is a manual recipe builder; we are paste-and-go with a security-specific verdict.
- Not yet another LOLBAS reference page. lolbas-project.github.io is the reference; we are the analyzer that *uses* it.

If a feature request would only make sense for a single customer's environment, it does not belong in this project.

## Core invariants

These are non-negotiable. Push back if a change would violate any of them.

1. **Universal input, universal output.** Input is a command-line string. Output is the same regardless of who pasted it. No tenant schemas, no per-org rules.
2. **The permalink is the product.** Every analysis must be reachable at a stable URL that renders identically for anyone who opens it.
3. **The free public tier stays free.** Paid features are team workspaces, private analyses, API rate limits — never the core paste-and-analyze flow.
4. **Privacy is load-bearing.** Analysts will paste real command lines from real incidents. If we leak, log carelessly, or sell data, they leave forever and never come back.
5. **Day-one usefulness, day-N moat.** The tool must be useful on the first paste with no corpus. The corpus accumulates from there and becomes the defensible moat.

## Architecture

Stack:
- **Frontend**: Next.js 15 (App Router), TypeScript, Tailwind. Deployed on Vercel.
- **Backend parsing service**: FastAPI (Python 3.12). Python is non-negotiable here — `bashlex`, the LOLBAS YAML files, MITRE ATT&CK STIX, and the decoder ecosystem are all Python-native. Deployed on Railway or Fly.io.
- **Database**: PostgreSQL via Supabase (free tier for MVP). Stores analyzed commands, public corpus, and user accounts when those exist.
- **Storage layout**: Public commands have stable hash-based slugs (`/c/<base32-hash>`). Private commands live behind auth.

Data flow on a paste:
1. Frontend POSTs the raw command to `/api/analyze`.
2. Backend parses with `bashlex`, runs decoder pipeline (base64 → UTF-16LE → gzip → recurse), matches against LOLBAS YAML, tags MITRE techniques, scores parent-process plausibility.
3. Backend writes to Postgres, returns a slug.
4. Frontend redirects to `/c/<slug>` which SSRs the analysis page.

The decoder pipeline is the hardest part to get right. Reference CyberChef recipes from `mattnotmax/cyberchef-recipes` and Airbus CERT's `minusone` for the patterns to handle.

## Out of scope (do not build these)

- Real-time tenant log ingestion
- Customer-specific detection rules
- Email/Slack alerting on customer environments
- A standalone SIEM dashboard
- Generic regex testing (regex101 owns this)
- Generic URL scanning (urlscan.io owns this)
- File sandboxing (ANY.RUN owns this)
- Integration with proprietary EDRs as a primary feature

If a user asks for these, the answer is "use the existing tool that does that, then paste the command back into us."

## Code conventions

- TypeScript strict mode on. No `any` without a comment explaining why.
- Python: type hints on every function signature. `ruff` for linting, `pytest` for tests.
- No client-side `localStorage` or `sessionStorage` for analysis data — everything goes through the backend so permalinks work across devices.
- Every API route has a Zod schema (TS) or Pydantic model (Python) for input validation. Untrusted input from analysts can include genuinely malicious command strings; treat it as data, never `eval`.
- Error responses are structured JSON with a stable `code` field, not raw stack traces.
- No third-party trackers (Google Analytics, Hotjar, Segment, etc.). If we need product analytics, use Plausible or self-hosted PostHog with explicit user consent.

## Testing

- Every parser, decoder, and pattern matcher gets unit tests with real-world adversarial samples (Lumma, Latrodectus, ClickFix payloads from public reports). Keep test fixtures in `backend/tests/fixtures/` with attribution comments linking the source blog post.
- Frontend gets Playwright tests for the paste → permalink flow.
- Integration tests run on every PR via GitHub Actions.

## Data handling rules

- **Public commands** (default): stored, indexed, included in the public corpus, shown in search. The slug is shareable.
- **Private commands** (paid tier later): stored encrypted, accessible only to the workspace, never in the public corpus.
- **Redaction**: before storing a public command, run a redaction pass that masks anything that looks like a credential, internal IP block, or hostname matching obvious internal patterns. False negatives here hurt analysts; err on the side of redacting and let users opt out per-paste.
- **Deletion**: users can delete their public submissions. The slug becomes a tombstone, not 404 — show "this command was deleted" so old links don't break confusingly.

## External data sources

- LOLBAS YAML: https://github.com/LOLBAS-Project/LOLBAS — vendor as a git submodule, refresh weekly.
- GTFOBins (Linux equivalent): https://github.com/GTFOBins/GTFOBins.github.io — same pattern.
- MITRE ATT&CK STIX: https://github.com/mitre/cti — pin a version, refresh quarterly.
- LOLDrivers: https://www.loldrivers.io/ — has a JSON API.

Do not call these APIs at request time. Bake them into the build, refresh on a schedule.

## What to ask the user before doing

- Database migrations that drop or rename columns
- Anything that changes the permalink format (would break existing shared links)
- Adding a paid feature to a path that was previously free
- Adding any third-party script tag to the frontend
- Changing the redaction rules for public commands

## Conventions that are easy to get wrong

- The slug format is `base32-encoded SHA256 of the normalized command`, truncated to 12 chars. Same command → same slug → idempotent. Do not switch to UUIDs without thinking through the deduplication implications.
- LOLBAS pattern matching uses argument similarity, not exact string match — see Palo Alto's `StringSimilarity` automation pattern (`difflib.SequenceMatcher`, threshold around 0.7). Exact match misses the obfuscation we exist to catch.
- When deobfuscating PowerShell, the first decode is almost always base64. The second is often UTF-16LE (look for `JAB` prefix in the b64). The third is often gzip (look for `H4sI` prefix in the b64). Recurse up to 5 layers, bail with a "complex obfuscation, manual review needed" verdict beyond that.

## Project status

Pre-v0.1. The first milestone is a paste box that returns parsed structure + base64 decode + LOLBAS lookup with a permalink. No accounts, no corpus search, no MITRE mapping yet. Get the loop working, then add depth.
