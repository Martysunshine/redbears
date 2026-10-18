"use client";

/**
 * The last line: only reached when the root layout itself fails, so it has to
 * render its own <html> and <body>. Plain styles on purpose — globals.css may
 * be what failed.
 */
export default function GlobalError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#0f0f0f",
          color: "#e8e8e8",
          fontFamily: "Inter, system-ui, sans-serif",
        }}
      >
        <div style={{ textAlign: "center", maxWidth: 360, padding: 24 }}>
          <p style={{ fontSize: 15, marginBottom: 4 }}>Oyster could not start.</p>
          <p style={{ fontSize: 14, opacity: 0.7, marginBottom: 20 }}>Nothing was lost. Reload to try again.</p>
          <button
            onClick={reset}
            style={{
              cursor: "pointer",
              padding: "8px 16px",
              borderRadius: 8,
              border: 0,
              background: "#e11d48",
              color: "#fff",
              fontSize: 14,
            }}
          >
            Try again
          </button>
        </div>
      </body>
    </html>
  );
}
