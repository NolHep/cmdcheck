export type Severity = "malicious" | "suspicious" | "notable" | "low" | "clean";

export type RuleOverride = { enabled: boolean; precision: number | null };

export type Tuning = {
  class_weights: Record<string, number>;
  points_low: number;
  points_medium: number;
  points_high: number;
  threshold_notable: number;
  threshold_suspicious: number;
  threshold_malicious: number;
  depth_step: number;
  correlation_bonus: number;
  encoding_base: number;
  encoding_step: number;
  lolbas_abuse_points: number;
  lolbas_abuse_similarity: number;
  lolbin_presence_points: number;
  loldrivers_points: number;
  recon_burst: number;
  rules: Record<string, RuleOverride>;
};

export type NumericKey = {
  [K in keyof Tuning]: Tuning[K] extends number ? K : never;
}[keyof Tuning];

export type Rule = {
  id: string;
  class: string;
  class_label: string;
  signal: string;
  confidence: "high" | "medium" | "low";
  precision: number;
  techniques: string[];
  requires_corroboration: boolean;
};

export type TuningState = {
  defaults: Tuning;
  active: Tuning;
  is_default: boolean;
  rules: Rule[];
};

export type VerdictSummary = {
  severity: Severity;
  label: string;
  detail: string;
  score: number;
  breakdown: { class: string; points: number; confidence?: string; precision?: number; max_depth?: number }[];
  classes: {
    name: string;
    label: string;
    confidence: string;
    precision: number;
    max_depth: number;
    signals: string[];
    rule_ids: string[];
  }[];
  layers: string[];
  lolbas: { name: string | null; arg_similarity?: number }[];
};

export type PreviewResult = { active: VerdictSummary; candidate: VerdictSummary };

export type BenchmarkRow = {
  id: string;
  set: string;
  kind: "attack" | "benign";
  command: string;
  tier: Severity;
  active: Severity;
  candidate: Severity;
  active_score: number;
  candidate_score: number;
  ok_active: boolean;
  ok_candidate: boolean;
};

export type BenchmarkResult =
  | { available: false }
  | {
      available: true;
      sets: {
        name: string;
        attacks: number;
        benign: number;
        active: { caught: number; over: number };
        candidate: { caught: number; over: number };
      }[];
      changes: BenchmarkRow[];
      failing: BenchmarkRow[];
      rule_hits: Record<string, { attack: number; benign: number }>;
    };
