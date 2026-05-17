import { z } from "zod";

const DecodeLayerSchema = z.object({
  layer: z.number().int().positive(),
  encoding: z.string(),
  value: z.string(),
});

const TechniqueDetailSchema = z.object({
  id: z.string(),
  name: z.string().nullable().optional(),
  tactic: z.string().nullable().optional(),
});

const LolbasMatchItemSchema = z.object({
  name: z.string().nullable(),
  description: z.string().nullable().optional(),
  url: z.string().nullable().optional(),
  techniques: z.array(z.string()),
  technique_details: z.array(TechniqueDetailSchema).optional(),
  functions: z.array(z.string()).optional(),
  similarity: z.number().optional(),
});

const LolbasMatchSchema = LolbasMatchItemSchema.nullable();

const GtfobinsMatchItemSchema = z.object({
  name: z.string(),
  functions: z.array(z.string()),
  url: z.string(),
  description: z.string().nullable().optional(),
});

const GtfobinsMatchSchema = GtfobinsMatchItemSchema.nullable().optional();

const LoldriversMatchSchema = z
  .object({
    filename: z.string(),
    category: z.string().optional(),
    tags: z.array(z.string()).optional(),
    resources: z.array(z.string()).optional(),
  })
  .nullable()
  .optional();

const ThreatClassSchema = z.object({
  name: z.string(),
  label: z.string(),
  confidence: z.enum(["high", "medium", "low"]),
  signals: z.array(z.string()),
  techniques: z.array(TechniqueDetailSchema).default([]),
});

const ParentVerdictSchema = z.object({
  parent: z.string(),
  child: z.string(),
  suspicion: z.enum(["high", "medium", "low", "benign"]),
  explanation: z.string(),
});

export const VtUrlResultSchema = z.object({
  url: z.string(),
  malicious: z.number(),
  suspicious: z.number(),
  harmless: z.number(),
  undetected: z.number(),
  total: z.number(),
});

export const ThreatIntelResultSchema = z.object({
  indicator: z.string(),
  type: z.enum(["url", "ip"]),
  virustotal: z.object({
    malicious: z.number(), suspicious: z.number(),
    harmless: z.number(), undetected: z.number(), total: z.number(),
  }).nullable().optional(),
  urlhaus: z.object({
    status: z.string(), threat: z.string().nullable().optional(),
    tags: z.array(z.string()).default([]),
    reference: z.string().nullable().optional(),
  }).nullable().optional(),
  threatfox: z.object({
    threat_type: z.string().nullable().optional(),
    malware: z.string().nullable().optional(),
    confidence: z.number().optional(),
    first_seen: z.string().nullable().optional(),
  }).nullable().optional(),
  greynoise: z.object({
    classification: z.string(),
    noise: z.boolean(), riot: z.boolean(),
    name: z.string().nullable().optional(),
  }).nullable().optional(),
  abuseipdb: z.object({
    score: z.number(), country: z.string().nullable().optional(),
    isp: z.string().nullable().optional(),
    total_reports: z.number(), usage_type: z.string().nullable().optional(),
  }).nullable().optional(),
  otx: z.object({
    pulses: z.number(),
    malware_families: z.array(z.string()).default([]),
  }).nullable().optional(),
});

export type ThreatIntelResult = z.infer<typeof ThreatIntelResultSchema>;

export const BinaryInCommandSchema = z.object({
  name: z.string(),
  source: z.enum(["lolbas", "gtfobins", "system", "threat_tool", "unknown"]),
  description: z.string().nullable().optional(),
  abuse_note: z.string().nullable().optional(),
  functions: z.array(z.string()).default([]),
  techniques: z.array(TechniqueDetailSchema).default([]),
  url: z.string().nullable().optional(),
});

// ── Workspace types ────────────────────────────────────────────────────────────

export const WorkspaceSchema = z.object({
  id: z.string(),
  name: z.string(),
  role: z.string().optional(),
  member_count: z.number().optional(),
  created_at: z.string(),
});

export const WorkspaceMemberSchema = z.object({
  id: z.string(),
  email: z.string(),
  role: z.string(),
  joined_at: z.string(),
});

export const WorkspaceDetailSchema = z.object({
  id: z.string(),
  name: z.string(),
  owner_id: z.string(),
  your_role: z.string(),
  created_at: z.string(),
  members: z.array(WorkspaceMemberSchema),
  recent_analyses: z.array(z.object({
    slug: z.string(),
    command: z.string(),
    threat_labels: z.array(z.string()),
    created_at: z.string(),
  })),
});

export const WorkspaceInviteSchema = z.object({
  id: z.string(),
  workspace_id: z.string(),
  email: z.string(),
  workspace_name: z.string().optional(),
  expires_at: z.string(),
  accepted: z.boolean().optional(),
  token: z.string().optional(),
});

// ── API key types ───────────────────────────────────────────────────────────────

export const ApiKeySchema = z.object({
  id: z.string(),
  name: z.string(),
  key_prefix: z.string(),
  created_at: z.string(),
  last_used_at: z.string().nullable().optional(),
  key: z.string().optional(), // returned once at creation
});

export type Workspace = z.infer<typeof WorkspaceSchema>;
export type WorkspaceDetail = z.infer<typeof WorkspaceDetailSchema>;
export type WorkspaceInvite = z.infer<typeof WorkspaceInviteSchema>;
export type ApiKey = z.infer<typeof ApiKeySchema>;

export const ThreatActorSchema = z.object({
  id: z.string(),
  name: z.string(),
  aliases: z.array(z.string()).default([]),
  country: z.string(),
  motivation: z.string(),
  description: z.string(),
  url: z.string(),
  matched_techniques: z.array(z.string()).default([]),
  overlap_count: z.number(),
  confidence: z.enum(["high", "medium", "low"]),
});

export type ThreatActor = z.infer<typeof ThreatActorSchema>;

export const AnalyzeResponseSchema = z.object({
  slug: z.string().regex(/^[A-Z2-7]{12}$/),
  command: z.string().optional(),
  parsed: z.unknown().nullable(),
  parsed_error: z.string().nullable().optional(),
  decoded_layers: z.array(DecodeLayerSchema),
  lolbas_match: LolbasMatchSchema,
  lolbas_matches: z.array(LolbasMatchItemSchema).default([]),
  gtfobins_match: GtfobinsMatchSchema,
  gtfobins_matches: z.array(GtfobinsMatchItemSchema).default([]),
  loldrivers_match: LoldriversMatchSchema,
  threat_classes: z.array(ThreatClassSchema).default([]),
  parent_verdict: ParentVerdictSchema.nullable().optional(),
  redacted: z.boolean().optional(),
  extracted_urls: z.array(z.string()).default([]),
  vt_results: z.array(VtUrlResultSchema).default([]),
  vt_configured: z.boolean().optional(),
  binaries_in_command: z.array(BinaryInCommandSchema).default([]),
  is_private: z.boolean().optional(),
  extracted_ips: z.array(z.string()).default([]),
  threat_intel: z.array(ThreatIntelResultSchema).default([]),
  threat_intel_configured: z.object({
    abuseipdb: z.boolean(),
    otx: z.boolean(),
  }).optional(),
  story: z.string().optional(),
  attributed_actors: z.array(ThreatActorSchema).default([]),
});

export const RecentItemSchema = z.object({
  slug: z.string(),
  command: z.string(),
  has_lolbas: z.boolean(),
  has_encoding: z.boolean(),
  threat_labels: z.array(z.string()),
  created_at: z.string(),
});

export type AnalyzeResponse = z.infer<typeof AnalyzeResponseSchema>;
export type DecodeLayer = z.infer<typeof DecodeLayerSchema>;
export type LolbasMatch = z.infer<typeof LolbasMatchSchema>;
export type GtfobinsMatch = z.infer<typeof GtfobinsMatchSchema>;
export type LoldriversMatch = z.infer<typeof LoldriversMatchSchema>;
export type ThreatClass = z.infer<typeof ThreatClassSchema>;
export type ParentVerdict = z.infer<typeof ParentVerdictSchema>;
export type TechniqueDetail = z.infer<typeof TechniqueDetailSchema>;
export type RecentItem = z.infer<typeof RecentItemSchema>;
export type VtUrlResult = z.infer<typeof VtUrlResultSchema>;
export type BinaryInCommand = z.infer<typeof BinaryInCommandSchema>;
export type TombstoneResponse = { deleted: true; slug: string };

function fetchWithTimeout(url: string, options: RequestInit = {}, ms = 15000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), ms);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(id));
}

export function apiBase(): string {
  if (typeof window === "undefined") {
    return process.env.BACKEND_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
  }
  const configured = process.env.NEXT_PUBLIC_API_URL;
  if (configured && !configured.includes("localhost") && !configured.includes("127.0.0.1")) {
    return configured;
  }
  const hostname = window.location.hostname;
  // Allow localhost and LAN addresses for dev; hard-fail on any other host so
  // analyst commands are never accidentally sent to an attacker-controlled origin.
  if (hostname === "localhost" || hostname === "127.0.0.1" || /^(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d+\.\d+$/.test(hostname)) {
    return `http://${hostname}:8000`;
  }
  throw new Error("NEXT_PUBLIC_API_URL is not configured. Set it to the backend URL before deploying.");
}

function extractDetail(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return null;
  const d = (body as Record<string, unknown>).detail;
  if (typeof d === "string") return d;
  if (typeof d === "object" && d !== null) {
    const nested = (d as Record<string, unknown>).detail;
    if (typeof nested === "string") return nested;
  }
  return null;
}

export async function postAnalyze(
  command: string,
  parentProcess?: string,
  options?: { isPrivate?: boolean; skipRedaction?: boolean; workspaceId?: string },
): Promise<AnalyzeResponse> {
  const isPrivate = options?.isPrivate ?? false;
  const skipRedaction = options?.skipRedaction ?? false;
  const workspaceId = options?.workspaceId ?? null;

  // Private submissions, redaction opt-out, and workspace tagging all go through
  // the Next.js API route so the server can attach the verified session email.
  const needsAuth = isPrivate || skipRedaction || !!workspaceId;
  const url = needsAuth ? "/api/analyze" : `${apiBase()}/analyze`;

  const res = await fetchWithTimeout(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      command,
      parent_process: parentProcess ?? null,
      is_private: isPrivate,
      skip_redaction: skipRedaction,
      workspace_id: workspaceId,
    }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(extractDetail(body) ?? `API error ${res.status}`);
  }
  const data = await res.json();
  return AnalyzeResponseSchema.parse(data);
}

export async function getAnalysis(
  slug: string
): Promise<AnalyzeResponse | TombstoneResponse | null> {
  const res = await fetchWithTimeout(`${apiBase()}/c/${slug}`, { cache: "no-store" });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`API error ${res.status}`);
  const data = await res.json();
  if (data.deleted) return { deleted: true, slug: data.slug };
  return AnalyzeResponseSchema.parse(data);
}

export async function deleteAnalysis(slug: string): Promise<void> {
  const res = await fetchWithTimeout(`${apiBase()}/c/${slug}`, { method: "DELETE" });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(extractDetail(body) ?? `API error ${res.status}`);
  }
}

export async function getRecentAnalyses(): Promise<RecentItem[]> {
  const res = await fetchWithTimeout(`${apiBase()}/recent`, { cache: "no-store" });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  const data = await res.json();
  return z.array(RecentItemSchema).parse(data);
}

export async function searchAnalyses(query: string): Promise<RecentItem[]> {
  const res = await fetchWithTimeout(
    `${apiBase()}/search?q=${encodeURIComponent(query)}&limit=30`
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(extractDetail(body) ?? `API error ${res.status}`);
  }
  const data = await res.json();
  return z.array(RecentItemSchema).parse(data);
}
