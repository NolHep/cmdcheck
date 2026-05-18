"use client";

import { useState, useRef, useEffect } from "react";
import Link from "next/link";
import { signOut } from "next-auth/react";

export default function MobileNav({
  loggedIn,
  email,
  role,
}: {
  loggedIn: boolean;
  email?: string;
  role?: "user" | "admin";
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

  const close = () => setOpen(false);

  return (
    <div className="relative md:hidden" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label="Menu"
        className="p-2 text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
      >
        {open ? (
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <line x1="4" y1="4" x2="16" y2="16" />
            <line x1="16" y1="4" x2="4" y2="16" />
          </svg>
        ) : (
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <line x1="3" y1="6" x2="17" y2="6" />
            <line x1="3" y1="10" x2="17" y2="10" />
            <line x1="3" y1="14" x2="17" y2="14" />
          </svg>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-56 bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-lg z-50 overflow-hidden">
          {loggedIn && email && (
            <div className="px-4 py-3 border-b border-[var(--border)]">
              <p className="text-xs text-[var(--muted)] truncate">{email}</p>
              {role === "admin" && (
                <span className="text-xs text-[var(--accent)] font-semibold">Admin</span>
              )}
            </div>
          )}

          <nav className="flex flex-col py-1">
            <Link href="/search" onClick={close} className="px-4 py-2.5 text-sm text-[var(--foreground)] hover:bg-[var(--border)] transition-colors">Search</Link>
            <Link href="/recent" onClick={close} className="px-4 py-2.5 text-sm text-[var(--foreground)] hover:bg-[var(--border)] transition-colors">Recent</Link>
            <Link href="/docs" onClick={close} className="px-4 py-2.5 text-sm text-[var(--foreground)] hover:bg-[var(--border)] transition-colors">Docs</Link>
            <Link href="/pricing" onClick={close} className="px-4 py-2.5 text-sm text-[var(--foreground)] hover:bg-[var(--border)] transition-colors">Pricing</Link>

            {loggedIn && (
              <>
                <div className="border-t border-[var(--border)] my-1" />
                <Link href="/account" onClick={close} className="px-4 py-2.5 text-sm text-[var(--foreground)] hover:bg-[var(--border)] transition-colors">Account</Link>
                <Link href="/workspaces" onClick={close} className="px-4 py-2.5 text-sm text-[var(--foreground)] hover:bg-[var(--border)] transition-colors">Workspaces</Link>
                <Link href="/account/api-keys" onClick={close} className="px-4 py-2.5 text-sm text-[var(--foreground)] hover:bg-[var(--border)] transition-colors">API keys</Link>
                {role === "admin" && (
                  <Link href="/admin" onClick={close} className="px-4 py-2.5 text-sm text-[var(--foreground)] hover:bg-[var(--border)] transition-colors">Admin</Link>
                )}
                <div className="border-t border-[var(--border)] my-1" />
                <button
                  onClick={() => { close(); signOut({ callbackUrl: "/" }); }}
                  className="w-full text-left px-4 py-2.5 text-sm text-[var(--muted)] hover:text-[var(--danger)] hover:bg-[var(--border)] transition-colors"
                >
                  Sign out
                </button>
              </>
            )}

            {!loggedIn && (
              <>
                <div className="border-t border-[var(--border)] my-1" />
                <Link href="/login" onClick={close} className="px-4 py-2.5 text-sm text-[var(--accent)] hover:bg-[var(--border)] transition-colors">Sign in</Link>
                <Link href="/register" onClick={close} className="px-4 py-2.5 text-sm text-[var(--foreground)] hover:bg-[var(--border)] transition-colors">Register</Link>
              </>
            )}
          </nav>
        </div>
      )}
    </div>
  );
}
