"use client";

import { useState } from "react";

export default function CopyLinkButton({ slug }: { slug: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    const url = `${window.location.origin}/c/${slug}`;
    await navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <button
      onClick={handleCopy}
      className="px-4 py-1.5 text-sm border border-[var(--border)] rounded-lg hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors"
    >
      {copied ? "Copied!" : "Copy link"}
    </button>
  );
}
