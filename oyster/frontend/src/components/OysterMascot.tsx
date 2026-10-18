"use client";

/**
 * OysterMascot — Oyster's identity from the real hero artwork, background removed
 * locally (public/logo-transparent.png). Transparent, no square, no white foam
 * (purple shell + pearl only). Animated with lightweight CSS transforms —
 * no GIF/video/Lottie/cloud render.
 *
 *   <OysterMascot size={40} />               // static open shell (sidebar / avatar)
 *   <OysterMascot size={200} animated />     // welcome: shell-open reveal + idle
 *
 * Replay the opening reveal by remounting (change the React `key`).
 */

interface OysterMascotProps {
  size?: number;
  animated?: boolean;
  playOpenAnimation?: boolean;
  idle?: boolean;
  variant?: "default" | "sidebar" | "welcome";
  className?: string;
}

// Raw <img> src values are NOT basePath-prefixed by Next (only next/image and
// <Link> are). In production this app is mounted at /oyster via the zone
// rewrite, so a bare "/logo-transparent.png" 404s — the mascot rendered as a
// broken-image icon in the sidebar and beside every message. Prefix it with
// the same build-time basePath the app is served under.
const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH || "";

export function OysterMascot({
  size = 48,
  animated = false,
  playOpenAnimation,
  idle,
  variant = "default",
  className = "",
}: OysterMascotProps) {
  const play = playOpenAnimation ?? animated;
  const doIdle = idle ?? animated;
  const active = play || doIdle;

  const cls = [
    "oyster-mascot",
    active ? "oyster-mascot--animated" : "",
    `oyster-mascot--${variant}`,
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <span className={cls} style={{ width: size, height: size }} role="img" aria-label="Oyster">
      <span className="om-bloom" aria-hidden="true" />
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img className="om-img" src={`${BASE_PATH}/logo-transparent.png`} alt="" draggable={false} />
      {active && (
        <span className="om-sparks" aria-hidden="true">
          <i className="om-spark om-spark-1" />
          <i className="om-spark om-spark-2" />
          <i className="om-spark om-spark-3" />
        </span>
      )}
    </span>
  );
}
