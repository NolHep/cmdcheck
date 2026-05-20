/**
 * ShellHawk wordmark glyph — minimalist hawk in flight, head-left.
 *
 * Single-path, fills via currentColor so it inherits whichever text color the
 * containing element uses (header accent in the nav, danger red in error
 * states if ever reused). 24x24 viewBox renders sharp at 16px (favicon size)
 * up through ~64px before detail loss matters.
 */
export default function HawkMark({
  className = "",
  size = 22,
  title = "ShellHawk",
}: {
  className?: string;
  size?: number;
  title?: string;
}) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      xmlns="http://www.w3.org/2000/svg"
      fill="currentColor"
      role="img"
      aria-label={title}
      className={className}
    >
      <title>{title}</title>
      {/* Outstretched wings + body + hooked beak silhouette */}
      <path d="M2 12.5
               L7.5 10.5
               L10.5 11.8
               L12.2 11.6
               L12.8 9.5
               L15.5 10.2
               L21 8.5
               L18.8 11.4
               L22 11.2
               L19.4 12.7
               L21.2 14.5
               L17.8 13.6
               L14.8 14.4
               L12.6 13.8
               L11.4 14
               L8 13.6
               L4.5 14
               Z" />
      {/* Sharp tail-feather flick — adds movement to an otherwise static silhouette */}
      <path d="M3 14.2 L6 15.8 L4.8 14.4 Z" opacity="0.85" />
    </svg>
  );
}
