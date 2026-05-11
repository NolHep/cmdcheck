"use client";

import { useState, useRef, useEffect } from "react";
import { signOut } from "next-auth/react";
import Link from "next/link";

export default function UserMenu({
  email,
  role,
}: {
  email: string;
  role: "user" | "admin";
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function close(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="text-[var(--muted)] text-sm hover:text-[var(--foreground)] transition-colors flex items-center gap-1.5"
      >
        <span className="w-6 h-6 rounded-full bg-[var(--border)] flex items-center justify-center text-xs font-bold text-[var(--foreground)]">
          {email[0].toUpperCase()}
        </span>
        <span className="hidden sm:inline">{email.split("@")[0]}</span>
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-48 bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-lg z-50 overflow-hidden">
          <div className="px-3 py-2 border-b border-[var(--border)]">
            <p className="text-xs text-[var(--muted)] truncate">{email}</p>
            {role === "admin" && (
              <span className="text-xs text-[var(--accent)] font-semibold">Admin</span>
            )}
          </div>
          {role === "admin" && (
            <Link
              href="/admin"
              onClick={() => setOpen(false)}
              className="block px-3 py-2 text-sm text-[var(--foreground)] hover:bg-[var(--border)] transition-colors"
            >
              Admin dashboard
            </Link>
          )}
          <button
            onClick={() => signOut({ callbackUrl: "/" })}
            className="w-full text-left px-3 py-2 text-sm text-[var(--muted)] hover:text-[var(--danger)] hover:bg-[var(--border)] transition-colors"
          >
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}
