import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "cmdcheck — command-line analyzer for incident responders",
  description:
    "Paste a suspicious command line and get structured analysis: deobfuscation, LOLBAS match, MITRE ATT&CK techniques, and a shareable permalink.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="h-full">
      <body className="min-h-full flex flex-col bg-[var(--background)] text-[var(--foreground)]">
        <header className="border-b border-[var(--border)] px-6 py-3 flex items-center gap-3">
          <a href="/" className="text-[var(--accent)] font-mono font-bold text-lg tracking-tight">
            cmdcheck
          </a>
          <span className="text-[var(--muted)] text-sm">command-line analyzer</span>
        </header>
        <main className="flex-1 flex flex-col">{children}</main>
      </body>
    </html>
  );
}
