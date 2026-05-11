export default function AnalysisLoading() {
  return (
    <div className="max-w-3xl mx-auto w-full px-4 py-8 flex flex-col gap-6 animate-pulse">
      {/* Verdict banner skeleton */}
      <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)] px-4 py-3 h-16" />

      {/* Command skeleton */}
      <div className="flex flex-col gap-2">
        <div className="h-3 w-24 bg-[var(--border)] rounded" />
        <div className="h-24 bg-[var(--surface)] border border-[var(--border)] rounded-lg" />
      </div>

      {/* Threat behavior skeleton */}
      <div className="flex flex-col gap-2">
        <div className="h-3 w-32 bg-[var(--border)] rounded" />
        <div className="h-16 bg-[var(--surface)] border border-[var(--border)] rounded-lg" />
        <div className="h-16 bg-[var(--surface)] border border-[var(--border)] rounded-lg" />
      </div>

      {/* Decode layers skeleton */}
      <div className="flex flex-col gap-2">
        <div className="h-3 w-40 bg-[var(--border)] rounded" />
        <div className="h-32 bg-[var(--surface)] border border-[var(--border)] rounded-lg" />
      </div>
    </div>
  );
}
