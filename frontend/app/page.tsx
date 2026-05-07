import CommandForm from "@/app/components/CommandForm";

export default function HomePage() {
  return (
    <div className="flex-1 flex flex-col items-center justify-start px-4 py-12 gap-8 max-w-3xl mx-auto w-full">
      <div className="text-center">
        <h1 className="text-3xl font-bold tracking-tight mb-2">
          Command-line analyzer
        </h1>
        <p className="text-[var(--muted)] text-base">
          Paste a suspicious command. Get deobfuscation, LOLBAS matching, and a
          shareable permalink — instantly.
        </p>
      </div>
      <CommandForm />
    </div>
  );
}
