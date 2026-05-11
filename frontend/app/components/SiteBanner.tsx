const BANNER_STYLE: Record<string, string> = {
  info: "bg-[#0d1f2d] border-[var(--accent)] text-[var(--foreground)]",
  warning: "bg-[#2a2000] border-yellow-600 text-yellow-200",
  danger: "bg-[#2d1515] border-[var(--danger)] text-red-200",
};

export default function SiteBanner({
  banner,
}: {
  banner: { enabled: boolean; message: string; type: string } | null;
}) {
  if (!banner?.enabled || !banner.message) return null;
  const style = BANNER_STYLE[banner.type] ?? BANNER_STYLE.info;
  return (
    <div className={`border-b px-6 py-2 text-sm text-center ${style}`}>
      {banner.message}
    </div>
  );
}
