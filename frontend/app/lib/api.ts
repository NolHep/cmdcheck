import { z } from "zod";

const DecodeLayerSchema = z.object({
  layer: z.number().int().positive(),
  encoding: z.string(),
  value: z.string(),
});

const LolbasMatchSchema = z
  .object({
    name: z.string().nullable(),
    description: z.string().nullable().optional(),
    url: z.string().nullable().optional(),
    techniques: z.array(z.string()),
    functions: z.array(z.string()).optional(),
    similarity: z.number().optional(),
  })
  .nullable();

export const AnalyzeResponseSchema = z.object({
  slug: z.string().regex(/^[A-Z2-7]{12}$/),
  command: z.string().optional(),
  parsed: z.unknown().nullable(),
  parsed_error: z.string().nullable().optional(),
  decoded_layers: z.array(DecodeLayerSchema),
  lolbas_match: LolbasMatchSchema,
});

export type AnalyzeResponse = z.infer<typeof AnalyzeResponseSchema>;
export type DecodeLayer = z.infer<typeof DecodeLayerSchema>;
export type LolbasMatch = z.infer<typeof LolbasMatchSchema>;

function apiBase(): string {
  // Server-side: prefer internal Docker URL, fall back to public URL
  if (typeof window === "undefined") {
    return process.env.BACKEND_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
  }
  return process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
}

export async function postAnalyze(command: string): Promise<AnalyzeResponse> {
  const res = await fetch(`${apiBase()}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail ?? `API error ${res.status}`);
  }
  const data = await res.json();
  return AnalyzeResponseSchema.parse(data);
}

export async function getAnalysis(slug: string): Promise<AnalyzeResponse | null> {
  const res = await fetch(`${apiBase()}/c/${slug}`, { cache: "no-store" });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`API error ${res.status}`);
  const data = await res.json();
  return AnalyzeResponseSchema.parse(data);
}
