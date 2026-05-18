import type { Metadata } from "next";
import Link from "next/link";
import { auth } from "@/auth";
import SiteBanner from "@/app/components/SiteBanner";
import UserMenu from "@/app/components/UserMenu";
import MobileNav from "@/app/components/MobileNav";
import { backendUrl } from "@/app/lib/api";
import "./globals.css";

export const metadata: Metadata = {
  title: "cmdcheck — command-line analyzer for incident responders",
  description:
    "Paste a suspicious command line and get structured analysis: deobfuscation, LOLBAS match, MITRE ATT&CK techniques, and a shareable permalink.",
};

async function getBanner() {
  try {
    const res = await fetch(`${backendUrl()}/settings/banner`, {
      next: { revalidate: 60 },
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export default async function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  const [session, banner] = await Promise.all([auth(), getBanner()]);

  return (
    <html lang="en" className="h-full" suppressHydrationWarning>
      <body className="min-h-full flex flex-col bg-[var(--background)] text-[var(--foreground)]">
        <SiteBanner banner={banner} />
        <header className="sticky top-0 z-40 border-b border-[var(--border)] px-6 py-3 flex items-center gap-4 bg-[rgba(13,17,23,0.85)] backdrop-blur-md">
          <Link href="/" className="text-[var(--accent)] font-mono font-bold text-lg tracking-tight">
            cmdcheck
          </Link>
          <span className="text-[var(--muted)] text-sm hidden sm:inline">command-line analyzer</span>
          <nav className="ml-auto flex items-center gap-4">
            {/* Desktop nav — hidden on mobile */}
            <div className="hidden md:flex items-center gap-4">
              <Link href="/search" className="text-[var(--muted)] text-sm hover:text-[var(--foreground)] transition-colors">
                Search
              </Link>
              <Link href="/recent" className="text-[var(--muted)] text-sm hover:text-[var(--foreground)] transition-colors">
                Recent
              </Link>
              <Link href="/docs" className="text-[var(--muted)] text-sm hover:text-[var(--foreground)] transition-colors">
                Docs
              </Link>
              {session?.user && (
                <Link href="/workspaces" className="text-[var(--muted)] text-sm hover:text-[var(--foreground)] transition-colors">
                  Workspaces
                </Link>
              )}
              {session?.user ? (
                <UserMenu email={session.user.email!} role={session.user.role} />
              ) : (
                <Link href="/login" className="text-[var(--muted)] text-sm hover:text-[var(--foreground)] transition-colors">
                  Sign in
                </Link>
              )}
            </div>

            {/* Mobile nav — hamburger, shown only on mobile */}
            <MobileNav
              loggedIn={!!session?.user}
              email={session?.user?.email ?? undefined}
              role={session?.user?.role}
            />
          </nav>
        </header>
        <main className="flex-1 flex flex-col">{children}</main>
        <footer className="border-t border-[var(--border)] px-6 py-3 flex items-center justify-between">
          <span className="text-[var(--muted)] text-xs">cmdcheck</span>
          <div className="flex items-center gap-4">
            <Link href="/feedback" className="text-[var(--muted)] text-xs hover:text-[var(--foreground)] transition-colors">
              Report a bug
            </Link>
          </div>
        </footer>
      </body>
    </html>
  );
}
