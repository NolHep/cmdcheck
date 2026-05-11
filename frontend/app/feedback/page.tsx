"use client";

import { useState } from "react";

function apiBase() {
  if (typeof window === "undefined") return "http://localhost:8000";
  if (process.env.NEXT_PUBLIC_API_URL) return process.env.NEXT_PUBLIC_API_URL;
  return `http://${window.location.hostname}:8000`;
}

export default function FeedbackPage() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "submitting" | "done" | "error">("idle");
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setState("submitting");
    setError("");
    try {
      const res = await fetch(`${apiBase()}/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          description,
          severity,
          contact_email: email || null,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body?.detail?.detail ?? "Submission failed. Please try again.");
        setState("error");
        return;
      }
      setState("done");
    } catch {
      setError("Network error. Please try again.");
      setState("error");
    }
  }

  if (state === "done") {
    return (
      <div className="max-w-lg mx-auto w-full px-4 py-16 text-center flex flex-col gap-4">
        <p className="text-4xl">✓</p>
        <h2 className="text-xl font-bold">Report submitted</h2>
        <p className="text-[var(--muted)] text-sm">
          Thanks for the report. We review all submissions and will follow up if you provided contact details.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-lg mx-auto w-full px-4 py-8">
      <h1 className="text-2xl font-bold mb-1">Report a bug</h1>
      <p className="text-[var(--muted)] text-sm mb-8">
        Found something broken or unexpected? Let us know. No account required.
      </p>

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="title" className="text-sm text-[var(--muted)]">Title <span className="text-[var(--danger)]">*</span></label>
          <input
            id="title"
            type="text"
            required
            minLength={3}
            maxLength={200}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Short description of the issue"
            className="bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)]"
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="severity" className="text-sm text-[var(--muted)]">Severity</label>
          <select
            id="severity"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)]"
          >
            <option value="low">Low — minor issue or cosmetic</option>
            <option value="medium">Medium — feature broken but workaround exists</option>
            <option value="high">High — blocking, data loss, or security</option>
          </select>
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="description" className="text-sm text-[var(--muted)]">Description <span className="text-[var(--danger)]">*</span></label>
          <textarea
            id="description"
            required
            minLength={10}
            maxLength={5000}
            rows={6}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Steps to reproduce, what you expected, what actually happened…"
            className="bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)] resize-y"
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="contact" className="text-sm text-[var(--muted)]">Contact email <span className="text-[var(--muted)] font-normal">(optional)</span></label>
          <input
            id="contact"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="we'll follow up if you'd like"
            className="bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--foreground)] focus:outline-none focus:border-[var(--accent)] placeholder:text-[var(--muted)]"
          />
        </div>

        {state === "error" && (
          <p className="text-[var(--danger)] text-sm" role="alert">{error}</p>
        )}

        <button
          type="submit"
          disabled={state === "submitting"}
          className="px-6 py-2 bg-[var(--accent)] text-[#0d1117] font-semibold rounded-lg disabled:opacity-40 hover:brightness-110 transition-all self-start"
        >
          {state === "submitting" ? "Submitting…" : "Submit report"}
        </button>
      </form>
    </div>
  );
}
