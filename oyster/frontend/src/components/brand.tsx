"use client";

// Red Orca brand bits used in Oyster's header: the settings wheel and the
// orca mark that links to the account dashboard.

// Raw <img> src is NOT basePath-prefixed by Next (only next/image and <Link>
// are), and this app is served at /oyster in production — see OysterMascot.
const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH || "";

/** Red Orca brand red (--orca-glow on the main site). */
export const ORCA_RED = "#e02027";

/**
 * A minimal gear: one ring, one hub, eight teeth. Turns slowly on its own and
 * spins up on hover — the motion lives in globals.css (.rw-wheel / .rw-btn) so
 * it can be disabled under prefers-reduced-motion.
 */
export function SettingsWheel({ size = 17 }: { size?: number }) {
  const teeth = Array.from({ length: 8 }, (_, i) => i * 45);
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={ORCA_RED}
      strokeWidth={1.7}
      strokeLinecap="round"
      className="rw-wheel"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="6.6" />
      <circle cx="12" cy="12" r="2.3" />
      {teeth.map((deg) => (
        <line key={deg} x1="12" y1="4.4" x2="12" y2="1.9" transform={`rotate(${deg} 12 12)`} />
      ))}
    </svg>
  );
}

/** The Red Orca mark. Wide silhouette — size is the WIDTH. */
export function RedOrcaMark({ width = 22, className = "" }: { width?: number; className?: string }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src={`${BASE_PATH}/red-orca-icon.svg`}
      alt=""
      width={width}
      height={Math.round((width * 677) / 1136)}
      className={className}
      aria-hidden="true"
    />
  );
}
