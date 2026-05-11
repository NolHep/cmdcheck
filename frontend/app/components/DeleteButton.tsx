"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { deleteAnalysis } from "@/app/lib/api";

export default function DeleteButton({ slug }: { slug: string }) {
  const router = useRouter();
  const [state, setState] = useState<"idle" | "confirming" | "deleting" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState("");

  async function handleDelete() {
    setState("deleting");
    try {
      await deleteAnalysis(slug);
      router.refresh();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Delete failed");
      setState("error");
    }
  }

  if (state === "error") {
    return <span className="text-[var(--danger)] text-xs">{errorMsg}</span>;
  }

  if (state === "deleting") {
    return <span className="text-[var(--muted)] text-xs">Deleting…</span>;
  }

  if (state === "confirming") {
    return (
      <div className="flex items-center gap-3">
        <span className="text-[var(--muted)] text-xs">Delete this analysis?</span>
        <button
          onClick={handleDelete}
          className="text-[var(--danger)] text-xs hover:underline"
        >
          Yes, delete
        </button>
        <button
          onClick={() => setState("idle")}
          className="text-[var(--muted)] text-xs hover:underline"
        >
          Cancel
        </button>
      </div>
    );
  }

  return (
    <button
      onClick={() => setState("confirming")}
      className="text-[var(--muted)] text-xs hover:text-[var(--danger)] transition-colors"
    >
      Delete analysis
    </button>
  );
}
