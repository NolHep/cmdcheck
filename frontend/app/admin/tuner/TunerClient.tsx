"use client";

import { useMemo, useState, useTransition } from "react";
import { benchmarkTuning, previewTuning, resetTuning, saveTuning } from "./actions";
import type {
  BenchmarkResult, BenchmarkRow, NumericKey, PreviewResult, Rule, Severity, Tuning, TuningState,
  VerdictSummary,
} from "./types";

/* ── static description of every knob ── */

type Knob = { key: NumericKey; label: string; help: string; step: number; min: number; max: number };

const THRESHOLDS: Knob[] = [
  { key: "threshold_notable", label: "Notable", help: "Score where “Notable — review recommended” starts.", step: 0.5, min: 0.5, max: 50 },
  { key: "threshold_suspicious", label: "Suspicious", help: "Score where “Suspicious” starts.", step: 0.5, min: 1, max: 80 },
  { key: "threshold_malicious", label: "Malicious", help: "Score where “Malicious” starts.", step: 0.5, min: 2, max: 100 },
];

const SCORING: Knob[] = [
  { key: "points_high", label: "High-confidence points", help: "Base points for a class whose best rule is high confidence.", step: 0.5, min: 0, max: 50 },
  { key: "points_medium", label: "Medium-confidence points", help: "Base points for a medium-confidence class.", step: 0.5, min: 0, max: 30 },
  { key: "points_low", label: "Low-confidence points", help: "Base points for a low-confidence class.", step: 0.5, min: 0, max: 20 },
  { key: "correlation_bonus", label: "Multi-stage bonus", help: "Added per extra class beyond the first (high counts 1, medium 0.5).", step: 0.5, min: 0, max: 20 },
  { key: "depth_step", label: "Hidden-signal multiplier", help: "Extra weight per decode layer a signal was hidden under (0.4 = +40% per layer).", step: 0.05, min: 0, max: 2 },
  { key: "encoding_base", label: "Encoded payload", help: "Points for an encoded payload even when nothing else fires.", step: 0.5, min: 0, max: 20 },
  { key: "encoding_step", label: "Per extra encoding layer", help: "Added for each further layer of encoding.", step: 0.5, min: 0, max: 10 },
  { key: "lolbas_abuse_points", label: "LOLBAS abuse pattern", help: "Points when arguments resemble a documented LOLBAS abuse example.", step: 0.5, min: 0, max: 20 },
  { key: "lolbas_abuse_similarity", label: "LOLBAS similarity needed", help: "How closely arguments must match an abuse example to earn those points (0–1).", step: 0.01, min: 0.4, max: 1 },
  { key: "lolbin_presence_points", label: "LOLBin merely present", help: "Points when a known-abusable binary appears and nothing else fires.", step: 0.5, min: 0, max: 10 },
  { key: "loldrivers_points", label: "Vulnerable driver (BYOVD)", help: "Points when a known-vulnerable driver is referenced.", step: 0.5, min: 0, max: 50 },
  { key: "recon_burst", label: "Discovery burst size", help: "Distinct enumeration commands in one paste that count as a burst.", step: 1, min: 2, max: 20 },
  { key: "recon_chain_bonus", label: "Discovery chain bonus", help: "Added when three or more medium or high discovery steps, or a dedicated AD-mapping tool, appear in one command.", step: 0.5, min: 0, max: 20 },
  { key: "signal_stack", label: "Signal stacking size", help: "Medium-confidence signals in one class that together count as high confidence.", step: 1, min: 2, max: 20 },
];

const SEVERITY_ORDER: Severity[] = ["clean", "low", "notable", "suspicious", "malicious"];
const SEVERITY_PILL: Record<Severity, string> = {
  malicious: "bg-[#2d1515] border-[var(--danger)] text-red-200",
  suspicious: "bg-[#2a1a0a] border-orange-500 text-orange-200",
  notable: "bg-[#2a2000] border-yellow-600 text-yellow-200",
  low: "bg-[var(--surface)] border-[var(--border)] text-[var(--muted)]",
  clean: "bg-[var(--surface)] border-[var(--border)] text-[var(--muted)]",
};

const inputBase =
  "bg-[var(--background)] border border-[var(--border)] rounded px-2 py-1 text-sm font-mono text-right focus:outline-none focus:border-[var(--accent)]";
const inputCls = `w-24 ${inputBase}`;
const btn =
  "text-sm px-3 py-1.5 rounded-lg border transition-colors disabled:opacity-40 disabled:cursor-not-allowed";
const btnGhost = `${btn} border-[var(--border)] text-[var(--muted)] hover:text-[var(--foreground)] hover:border-[var(--accent)]`;
const btnPrimary = `${btn} border-[var(--accent)] bg-[var(--accent)] text-[#0d1117] font-semibold hover:opacity-90`;
const card = "border border-[var(--border)] rounded-lg bg-[var(--surface)]";

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const pct = (n: number, d: number) => (d ? `${((100 * n) / d).toFixed(1)}%` : "–");

function SeverityPill({ s }: { s: Severity }) {
  return (
    <span className={`text-[11px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded border ${SEVERITY_PILL[s]}`}>
      {s}
    </span>
  );
}

/* ── main ── */

export default function TunerClient({ initial }: { initial: TuningState }) {
  const [state, setState] = useState(initial);
  const [draft, setDraft] = useState<Tuning>(initial.active);
  const [bench, setBench] = useState<{ result: BenchmarkResult; of: string } | null>(null);
  const [acceptRegression, setAcceptRegression] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<"bench" | "save" | "reset" | null>(null);

  const defaults = state.defaults;
  const dirty = !same(draft, state.active);
  const draftKey = JSON.stringify(draft);
  const benchFresh = bench?.of === draftKey;
  const benchResult = benchFresh && bench?.result.available ? bench.result : null;
  const corpusMissing = benchFresh && bench?.result.available === false;

  const regression = useMemo(() => {
    if (!benchResult) return null;
    const lostAttacks = benchResult.sets.reduce((n, s) => n + Math.max(0, s.active.caught - s.candidate.caught), 0);
    const newFalse = benchResult.sets.reduce((n, s) => n + Math.max(0, s.candidate.over - s.active.over), 0);
    return lostAttacks || newFalse ? { lostAttacks, newFalse } : null;
  }, [benchResult]);

  const canSave = dirty && (corpusMissing || (!!benchResult && (!regression || acceptRegression)));

  const setNum = (key: NumericKey, value: number) => {
    if (Number.isNaN(value)) return;
    setDraft((d) => ({ ...d, [key]: value }));
    setMessage(null);
  };
  const setWeight = (name: string, value: number) => {
    if (Number.isNaN(value)) return;
    setDraft((d) => ({ ...d, class_weights: { ...d.class_weights, [name]: value } }));
    setMessage(null);
  };
  const setRule = (rule: Rule, patch: Partial<{ enabled: boolean; precision: number | null }>) => {
    setDraft((d) => {
      const current = d.rules[rule.id] ?? { enabled: true, precision: null };
      const next = { ...current, ...patch };
      if (next.precision !== null && Math.abs(next.precision - rule.precision) < 1e-9) next.precision = null;
      const rules = { ...d.rules };
      if (next.enabled && next.precision === null) delete rules[rule.id];
      else rules[rule.id] = next;
      return { ...d, rules };
    });
    setMessage(null);
  };

  const run = (which: "bench" | "save" | "reset", fn: () => Promise<void>) => {
    setBusy(which);
    startTransition(async () => {
      try {
        await fn();
      } finally {
        setBusy(null);
      }
    });
  };

  const onBenchmark = () =>
    run("bench", async () => {
      const res = await benchmarkTuning(draft);
      if (res.ok) {
        setBench({ result: res.data, of: draftKey });
        setAcceptRegression(false);
        setMessage(null);
      } else setMessage({ kind: "error", text: res.error });
    });

  const onSave = () =>
    run("save", async () => {
      const res = await saveTuning(draft);
      if (res.ok) {
        setState(res.data);
        setDraft(res.data.active);
        setBench(null);
        setMessage({ kind: "ok", text: "Saved. New analyses now use this tuning." });
      } else setMessage({ kind: "error", text: res.error });
    });

  const onReset = () =>
    run("reset", async () => {
      const res = await resetTuning();
      if (res.ok) {
        setState(res.data);
        setDraft(res.data.active);
        setBench(null);
        setMessage({ kind: "ok", text: "Defaults restored and active." });
      } else setMessage({ kind: "error", text: res.error });
    });

  const changedCount =
    [...THRESHOLDS, ...SCORING].filter((k) => draft[k.key] !== defaults[k.key]).length +
    Object.keys(draft.class_weights).filter((c) => draft.class_weights[c] !== defaults.class_weights[c]).length +
    Object.keys(draft.rules).length;

  return (
    <div className="flex flex-col gap-8">
      {/* ── action bar ── */}
      <div className={`${card} px-4 py-3 flex items-center gap-x-3 gap-y-2 flex-wrap sticky top-2 z-10`}>
        <span className={`text-xs px-2 py-1 rounded border ${state.is_default ? "border-[var(--border)] text-[var(--muted)]" : "border-[var(--accent)] text-[var(--accent)]"}`}>
          {state.is_default ? "Defaults active" : "Custom tuning active"}
        </span>
        <span className="text-xs text-[var(--muted)]">
          {dirty ? "Unsaved changes" : "No unsaved changes"} · {changedCount} setting{changedCount === 1 ? " differs" : "s differ"} from defaults
        </span>
        <div className="hidden sm:block flex-1" />
        <button className={btnGhost} disabled={!dirty || pending} onClick={() => { setDraft(state.active); setMessage(null); }}>
          Discard changes
        </button>
        <button className={btnGhost} disabled={pending || same(draft, defaults)} onClick={() => { setDraft(defaults); setMessage(null); }}>
          Load defaults
        </button>
        <button className={btnGhost} disabled={pending} onClick={onBenchmark}>
          {busy === "bench" ? "Running…" : "Run benchmark"}
        </button>
        <button className={btnPrimary} disabled={!canSave || pending} onClick={onSave}
          title={canSave ? "" : dirty ? "Run the benchmark on these settings first" : "Nothing to save"}>
          {busy === "save" ? "Saving…" : "Save & activate"}
        </button>
      </div>

      {message && (
        <div role="status" className={`rounded-lg border px-4 py-2 text-sm ${message.kind === "ok" ? "border-[var(--success)] text-[var(--success)]" : "border-[var(--danger)] text-red-200"}`}>
          {message.text}
        </div>
      )}
      {dirty && !benchFresh && (
        <p className="text-xs text-[var(--muted)] -mt-4">
          Run the benchmark on these settings to see what they change — saving is enabled once you have.
        </p>
      )}

      <Benchmark bench={benchFresh ? bench!.result : null} regression={regression}
        accept={acceptRegression} onAccept={setAcceptRegression} />

      <CommandPreview draft={draft} />

      {/* ── thresholds ── */}
      <section>
        <h2 className="section-label">Verdict thresholds</h2>
        <div className={`${card} p-4 flex flex-col gap-4`}>
          <ThresholdBar t={draft} />
          <div className="grid sm:grid-cols-3 gap-4">
            {THRESHOLDS.map((k) => (
              <NumberField key={k.key} knob={k} value={draft[k.key]} def={defaults[k.key]} onChange={(v) => setNum(k.key, v)} />
            ))}
          </div>
          {!(draft.threshold_notable < draft.threshold_suspicious && draft.threshold_suspicious < draft.threshold_malicious) && (
            <p className="text-xs text-red-300">Thresholds must increase: notable &lt; suspicious &lt; malicious.</p>
          )}
        </div>
      </section>

      {/* ── class weights ── */}
      <section>
        <h2 className="section-label">Class weights — how much each kind of behaviour matters</h2>
        <div className={`${card} p-4 grid sm:grid-cols-2 gap-x-8 gap-y-3`}>
          {Object.keys(defaults.class_weights).map((name) => {
            const value = draft.class_weights[name] ?? defaults.class_weights[name];
            const changed = value !== defaults.class_weights[name];
            return (
              <label key={name} className="flex items-center gap-3 text-sm">
                <span className={`w-24 sm:w-40 shrink-0 ${changed ? "text-[var(--accent)]" : ""}`}>{name.replace(/_/g, " ")}</span>
                <input type="range" min={0} max={3} step={0.1} value={value} className="flex-1 min-w-0 accent-[var(--accent)]"
                  onChange={(e) => setWeight(name, parseFloat(e.target.value))} aria-label={`${name} weight`} />
                <input type="number" min={0} max={5} step={0.1} value={value} className={`w-14 sm:w-16 ${inputBase}`}
                  onChange={(e) => setWeight(name, parseFloat(e.target.value))} aria-label={`${name} weight value`} />
                <span className="hidden sm:inline w-14 text-xs text-[var(--muted)]">def {defaults.class_weights[name]}</span>
              </label>
            );
          })}
        </div>
      </section>

      {/* ── scoring ── */}
      <section>
        <h2 className="section-label">Scoring</h2>
        <div className={`${card} p-4 grid sm:grid-cols-2 gap-x-8 gap-y-4`}>
          {SCORING.map((k) => (
            <NumberField key={k.key} knob={k} value={draft[k.key]} def={defaults[k.key]} onChange={(v) => setNum(k.key, v)} />
          ))}
        </div>
      </section>

      <Rules rules={state.rules} draft={draft} hits={benchResult?.rule_hits ?? null} onChange={setRule} />

      <div className="flex justify-end">
        <button className={`${btn} border-[var(--danger)] text-red-300 hover:bg-[#2d1515]`} disabled={pending || state.is_default} onClick={onReset}>
          {busy === "reset" ? "Resetting…" : "Reset saved tuning to defaults"}
        </button>
      </div>
    </div>
  );
}

/* ── pieces ── */

function NumberField({ knob, value, def, onChange }: { knob: Knob; value: number; def: number; onChange: (v: number) => void }) {
  const changed = value !== def;
  return (
    <label className="flex items-start justify-between gap-3">
      <span className="min-w-0">
        <span className={`text-sm ${changed ? "text-[var(--accent)]" : ""}`}>{knob.label}</span>
        <span className="block text-xs text-[var(--muted)] leading-snug">{knob.help}</span>
      </span>
      <span className="flex flex-col items-end gap-0.5 shrink-0">
        <input type="number" className={inputCls} value={value} step={knob.step} min={knob.min} max={knob.max}
          onChange={(e) => onChange(parseFloat(e.target.value))} aria-label={knob.label} />
        <span className="text-[11px] text-[var(--muted)]">
          default {def}
          {changed && (
            <button type="button" className="ml-1.5 text-[var(--accent)] hover:underline" onClick={() => onChange(def)}>reset</button>
          )}
        </span>
      </span>
    </label>
  );
}

function ThresholdBar({ t }: { t: Tuning }) {
  const max = Math.max(t.threshold_malicious * 1.5, 1);
  const at = (v: number) => `${Math.min(100, (100 * v) / max)}%`;
  const seg = [
    { label: "low", from: 0, to: t.threshold_notable, cls: "bg-[var(--border)]" },
    { label: "notable", from: t.threshold_notable, to: t.threshold_suspicious, cls: "bg-yellow-700" },
    { label: "suspicious", from: t.threshold_suspicious, to: t.threshold_malicious, cls: "bg-orange-600" },
    { label: "malicious", from: t.threshold_malicious, to: max, cls: "bg-[var(--danger)]" },
  ];
  return (
    <div aria-hidden>
      <div className="flex h-3 rounded overflow-hidden">
        {seg.map((s) => (
          <div key={s.label} className={s.cls} style={{ width: `${Math.max(0, (100 * (s.to - s.from)) / max)}%` }} />
        ))}
      </div>
      <div className="relative h-4 text-[11px] text-[var(--muted)] mt-1">
        <span className="absolute left-0">0</span>
        {[t.threshold_notable, t.threshold_suspicious, t.threshold_malicious].map((v, i) => (
          <span key={i} className="absolute -translate-x-1/2" style={{ left: at(v) }}>{v}</span>
        ))}
      </div>
    </div>
  );
}

function Benchmark({ bench, regression, accept, onAccept }: {
  bench: BenchmarkResult | null;
  regression: { lostAttacks: number; newFalse: number } | null;
  accept: boolean;
  onAccept: (v: boolean) => void;
}) {
  return (
    <section>
      <h2 className="section-label">Benchmark — labelled corpus, active vs. these settings</h2>
      {!bench ? (
        <div className={`${card} px-4 py-3 text-sm text-[var(--muted)]`}>
          Not run for the current settings. “Run benchmark” scores every labelled attack and benign command twice — once
          with what is live, once with what is on this page.
        </div>
      ) : !bench.available ? (
        <div className={`${card} px-4 py-3 text-sm text-[var(--muted)]`}>
          The labelled corpus is not present in this backend build, so changes cannot be measured here. Saving is allowed, unmeasured.
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          <div className={`${card} overflow-x-auto`}>
            <table className="w-full text-sm">
              <thead className="text-xs text-[var(--muted)] text-left">
                <tr className="border-b border-[var(--border)]">
                  <th className="px-4 py-2 font-medium">Set</th>
                  <th className="px-4 py-2 font-medium">Attacks caught — active</th>
                  <th className="px-4 py-2 font-medium">→ these settings</th>
                  <th className="px-4 py-2 font-medium">Benign over tier — active</th>
                  <th className="px-4 py-2 font-medium">→ these settings</th>
                </tr>
              </thead>
              <tbody>
                {bench.sets.map((s) => {
                  const worseA = s.candidate.caught < s.active.caught;
                  const betterA = s.candidate.caught > s.active.caught;
                  const worseB = s.candidate.over > s.active.over;
                  const betterB = s.candidate.over < s.active.over;
                  return (
                    <tr key={s.name} className="border-b border-[var(--border-subtle)] last:border-0 font-mono text-xs">
                      <td className="px-4 py-2 font-sans text-sm">{s.name}</td>
                      <td className="px-4 py-2">{s.active.caught}/{s.attacks} ({pct(s.active.caught, s.attacks)})</td>
                      <td className={`px-4 py-2 ${worseA ? "text-red-300" : betterA ? "text-[var(--success)]" : ""}`}>
                        {s.candidate.caught}/{s.attacks} ({pct(s.candidate.caught, s.attacks)})
                      </td>
                      <td className="px-4 py-2">{s.active.over}/{s.benign} ({pct(s.active.over, s.benign)})</td>
                      <td className={`px-4 py-2 ${worseB ? "text-red-300" : betterB ? "text-[var(--success)]" : ""}`}>
                        {s.candidate.over}/{s.benign} ({pct(s.candidate.over, s.benign)})
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {regression && (
            <label className="flex items-start gap-2 rounded-lg border border-[var(--danger)] bg-[#2d1515] px-4 py-3 text-sm">
              <input type="checkbox" className="mt-0.5" checked={accept} onChange={(e) => onAccept(e.target.checked)} />
              <span>
                These settings are worse than what is live:{" "}
                {regression.lostAttacks > 0 && <b>{regression.lostAttacks} attack{regression.lostAttacks === 1 ? "" : "s"} no longer reach their tier</b>}
                {regression.lostAttacks > 0 && regression.newFalse > 0 && " and "}
                {regression.newFalse > 0 && <b>{regression.newFalse} more benign command{regression.newFalse === 1 ? "" : "s"} rated too high</b>}
                . Tick to allow saving anyway.
              </span>
            </label>
          )}
          <RowList title={`Verdicts that change (${bench.changes.length})`} rows={bench.changes} open={bench.changes.length > 0 && bench.changes.length <= 12} />
          <RowList title={`Wrong under these settings (${bench.failing.length})`} rows={bench.failing} open={false} />
        </div>
      )}
    </section>
  );
}

function RowList({ title, rows, open }: { title: string; rows: BenchmarkRow[]; open: boolean }) {
  if (rows.length === 0) return <p className="text-xs text-[var(--muted)]">{title.replace(/\(\d+\)/, "(none)")}</p>;
  return (
    <details className={`${card} group`} open={open}>
      <summary className="cursor-pointer px-4 py-2 text-sm list-none flex items-center gap-1.5">
        <span className="group-open:rotate-90 transition-transform inline-block text-[var(--muted)]">▶</span>
        {title}
      </summary>
      <div className="max-h-96 overflow-auto border-t border-[var(--border)]">
        {rows.map((r) => (
          <div key={`${r.set}-${r.id}`} className="px-4 py-2 border-b border-[var(--border-subtle)] last:border-0 flex flex-col gap-1">
            <div className="flex items-center gap-2 flex-wrap text-xs">
              <span className={r.kind === "attack" ? "text-red-300" : "text-[var(--success)]"}>{r.kind}</span>
              <span className="font-mono text-[var(--muted)]">{r.id}</span>
              <span className="text-[var(--muted)]">{r.kind === "attack" ? "needs ≥" : "allowed ≤"} {r.tier}</span>
              <span className="flex-1" />
              <SeverityPill s={r.active} />
              <span className="text-[var(--muted)]">→</span>
              <SeverityPill s={r.candidate} />
              <span className={r.ok_candidate ? "text-[var(--success)]" : "text-red-300"}>{r.ok_candidate ? "ok" : "wrong"}</span>
            </div>
            <code className="font-mono text-[11px] text-[var(--muted)] break-all">{r.command}</code>
          </div>
        ))}
      </div>
    </details>
  );
}

function CommandPreview({ draft }: { draft: Tuning }) {
  const [command, setCommand] = useState("");
  const [result, setResult] = useState<PreviewResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const go = () =>
    startTransition(async () => {
      const res = await previewTuning(command, draft);
      if (res.ok) { setResult(res.data); setError(null); }
      else { setResult(null); setError(res.error); }
    });

  return (
    <section>
      <h2 className="section-label">Try a command — nothing is stored</h2>
      <div className={`${card} p-4 flex flex-col gap-3`}>
        <textarea value={command} onChange={(e) => setCommand(e.target.value)} rows={3} spellCheck={false}
          placeholder="Paste a command to see its verdict with the live tuning and with the settings on this page"
          className="w-full bg-[var(--background)] border border-[var(--border)] rounded-lg px-3 py-2 font-mono text-xs focus:outline-none focus:border-[var(--accent)]" />
        <div className="flex items-center gap-3">
          <button className={btnGhost} disabled={pending || !command.trim()} onClick={go}>
            {pending ? "Scoring…" : "Compare"}
          </button>
          {error && <span className="text-xs text-red-300">{error}</span>}
        </div>
        {result && (
          <div className="grid md:grid-cols-2 gap-3">
            <VerdictCard title="Live tuning" v={result.active} />
            <VerdictCard title="Settings on this page" v={result.candidate} other={result.active} />
          </div>
        )}
      </div>
    </section>
  );
}

function VerdictCard({ title, v, other }: { title: string; v: VerdictSummary; other?: VerdictSummary }) {
  const moved = other ? SEVERITY_ORDER.indexOf(v.severity) - SEVERITY_ORDER.indexOf(other.severity) : 0;
  return (
    <div className="border border-[var(--border)] rounded-lg p-3 flex flex-col gap-2 bg-[var(--background)]">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-[var(--muted)]">{title}</span>
        <span className="flex-1" />
        {moved !== 0 && <span className="text-xs text-[var(--accent)]">{moved > 0 ? "raised" : "lowered"}</span>}
        <SeverityPill s={v.severity} />
        <span className="font-mono text-sm">{v.score}</span>
      </div>
      <p className="text-xs text-[var(--muted)]">{v.detail}</p>
      <table className="text-xs w-full">
        <tbody>
          {v.breakdown.map((b, i) => (
            <tr key={i} className="border-t border-[var(--border-subtle)]">
              <td className="py-1 pr-2">{b.class.startsWith("_") ? b.class.slice(1).replace(/_/g, " ") : b.class.replace(/_/g, " ")}</td>
              <td className="py-1 pr-2 text-[var(--muted)]">
                {b.confidence ?? ""}{b.precision !== undefined && b.precision < 1 ? ` · precision ${b.precision}` : ""}
                {b.max_depth ? ` · depth ${b.max_depth}` : ""}
              </td>
              <td className="py-1 text-right font-mono">{b.points > 0 ? "+" : ""}{b.points}</td>
            </tr>
          ))}
          {v.breakdown.length === 0 && <tr><td className="py-1 text-[var(--muted)]">No findings.</td></tr>}
        </tbody>
      </table>
      {v.classes.length > 0 && (
        <ul className="text-[11px] text-[var(--muted)] list-disc pl-4">
          {v.classes.flatMap((c) => c.signals.map((s) => <li key={`${c.name}-${s}`}>{s}</li>))}
        </ul>
      )}
      {v.layers.length > 0 && <p className="text-[11px] text-[var(--muted)]">Decoded: {v.layers.join(" → ")}</p>}
    </div>
  );
}

function Rules({ rules, draft, hits, onChange }: {
  rules: Rule[];
  draft: Tuning;
  hits: Record<string, { attack: number; benign: number }> | null;
  onChange: (rule: Rule, patch: Partial<{ enabled: boolean; precision: number | null }>) => void;
}) {
  const [query, setQuery] = useState("");
  const [cls, setCls] = useState("all");
  const [only, setOnly] = useState<"all" | "changed" | "benign">("all");
  const classes = useMemo(() => Array.from(new Map(rules.map((r) => [r.class, r.class_label])).entries()), [rules]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rules.filter((r) => {
      if (cls !== "all" && r.class !== cls) return false;
      if (only === "changed" && !draft.rules[r.id]) return false;
      if (only === "benign" && !(hits && (hits[r.id]?.benign ?? 0) > 0)) return false;
      return !q || r.signal.toLowerCase().includes(q) || r.techniques.some((t) => t.toLowerCase().includes(q));
    });
  }, [rules, query, cls, only, draft.rules, hits]);

  return (
    <section>
      <h2 className="section-label">Rules — {rules.length} total, {Object.keys(draft.rules).length} overridden</h2>
      <div className={`${card} flex flex-col`}>
        <div className="p-3 flex items-center gap-2 flex-wrap border-b border-[var(--border)]">
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search signal text or technique ID"
            className="flex-1 min-w-48 bg-[var(--background)] border border-[var(--border)] rounded px-2 py-1 text-sm focus:outline-none focus:border-[var(--accent)]" />
          <select value={cls} onChange={(e) => setCls(e.target.value)} aria-label="Filter by class"
            className="bg-[var(--background)] border border-[var(--border)] rounded px-2 py-1 text-sm">
            <option value="all">All classes</option>
            {classes.map(([name, label]) => <option key={name} value={name}>{label}</option>)}
          </select>
          <select value={only} onChange={(e) => setOnly(e.target.value as typeof only)} aria-label="Filter rules"
            className="bg-[var(--background)] border border-[var(--border)] rounded px-2 py-1 text-sm">
            <option value="all">All rules</option>
            <option value="changed">Overridden only</option>
            <option value="benign" disabled={!hits}>Fires on benign commands{hits ? "" : " (run benchmark)"}</option>
          </select>
          <span className="text-xs text-[var(--muted)]">{shown.length} shown</span>
        </div>
        <div className="max-h-[32rem] overflow-auto">
          <table className="w-full text-sm">
            <thead className="text-xs text-[var(--muted)] text-left sticky top-0 bg-[var(--surface)]">
              <tr className="border-b border-[var(--border)]">
                <th className="px-3 py-2 font-medium">On</th>
                <th className="px-3 py-2 font-medium">Signal</th>
                <th className="px-3 py-2 font-medium">Confidence</th>
                <th className="px-3 py-2 font-medium">Precision</th>
                <th className="px-3 py-2 font-medium whitespace-nowrap" title="Benchmark commands this rule fired on, under the settings on this page">Hits: attack / benign</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => {
                const ov = draft.rules[r.id];
                const enabled = ov?.enabled ?? true;
                const precision = ov?.precision ?? r.precision;
                const h = hits?.[r.id];
                return (
                  <tr key={r.id} className={`border-b border-[var(--border-subtle)] last:border-0 ${enabled ? "" : "opacity-50"}`}>
                    <td className="px-3 py-2 align-top">
                      <input type="checkbox" checked={enabled} aria-label={`Enable rule: ${r.signal}`}
                        onChange={(e) => onChange(r, { enabled: e.target.checked })} />
                    </td>
                    <td className="px-3 py-2">
                      <span className={ov ? "text-[var(--accent)]" : ""}>{r.signal}</span>
                      <span className="block text-[11px] text-[var(--muted)]">
                        {r.class_label}{r.techniques.length ? ` · ${r.techniques.join(", ")}` : ""}
                        {r.requires_corroboration ? " · only counts alongside another rule in its class" : ""}
                      </span>
                    </td>
                    <td className="px-3 py-2 align-top text-xs uppercase text-[var(--muted)]">{r.confidence}</td>
                    <td className="px-3 py-2 align-top whitespace-nowrap">
                      <input type="number" min={0.05} max={1} step={0.05} value={precision} className={`w-20 ${inputBase}`}
                        aria-label={`Precision for rule: ${r.signal}`}
                        onChange={(e) => { const v = parseFloat(e.target.value); if (!Number.isNaN(v)) onChange(r, { precision: v }); }} />
                      {ov?.precision != null && <span className="ml-1.5 text-[11px] text-[var(--muted)]">def {r.precision}</span>}
                    </td>
                    <td className="px-3 py-2 align-top font-mono text-xs">
                      {h ? <><span>{h.attack}</span> / <span className={h.benign > 0 ? "text-yellow-300" : ""}>{h.benign}</span></> : hits ? "0 / 0" : "–"}
                    </td>
                  </tr>
                );
              })}
              {shown.length === 0 && (
                <tr><td colSpan={5} className="px-3 py-6 text-center text-[var(--muted)] text-sm">No rules match.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
