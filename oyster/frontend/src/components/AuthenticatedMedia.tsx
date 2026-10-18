"use client";

import { forwardRef, useEffect, useState } from "react";
import type { ImgHTMLAttributes, VideoHTMLAttributes } from "react";
import { authFetch } from "@/lib/api";

type Props = ImgHTMLAttributes<HTMLImageElement> & { src: string };

/**
 * Media routes are authenticated. A normal img/video URL cannot attach the
 * Supabase bearer, so signed-in previews used to render as broken images.
 * Fetching a short-lived blob URL keeps the existing server-side ownership
 * checks and works for both anonymous and signed-in sessions.
 */
export function AuthenticatedImage({ src, alt = "", ...props }: Props) {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let url: string | null = null;
    setObjectUrl(null);
    authFetch(src)
      .then(async (response) => {
        if (!response.ok) throw new Error(`media request failed: ${response.status}`);
        const blob = await response.blob();
        if (cancelled) return;
        url = URL.createObjectURL(blob);
        setObjectUrl(url);
      })
      .catch(() => {
        if (!cancelled) setObjectUrl(null);
      });
    return () => {
      cancelled = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [src]);

  return <img {...props} src={objectUrl ?? undefined} alt={alt} />;
}

export const AuthenticatedVideo = forwardRef<HTMLVideoElement, VideoHTMLAttributes<HTMLVideoElement> & { src: string }>(function AuthenticatedVideo({ src, ...props }, ref) {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let url: string | null = null;
    setObjectUrl(null);
    authFetch(src)
      .then(async (response) => {
        if (!response.ok) throw new Error(`media request failed: ${response.status}`);
        const blob = await response.blob();
        if (cancelled) return;
        url = URL.createObjectURL(blob);
        setObjectUrl(url);
      })
      .catch(() => {
        if (!cancelled) setObjectUrl(null);
      });
    return () => {
      cancelled = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [src]);

  return <video {...props} ref={ref} src={objectUrl ?? undefined} />;
});
