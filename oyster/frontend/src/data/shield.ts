// Curated, read-only snapshot of the CyberMat Shield scanner
// (github.com/Martysunshine/cybermat-shield). This is REFERENCE ONLY — Oyster
// never runs any of it. The Shield panel renders these blocks with copy
// buttons so an operator can paste them into their own terminal and run the
// scanner locally on their own machine.

export const SHIELD_REPO = "https://github.com/Martysunshine/cybermat-shield";
export const SHIELD_TAGLINE =
  "Local-first application security scanner — finds secrets, vulnerabilities, misconfigurations, and access-control bugs in your codebase. Runs entirely on your machine; nothing leaves your computer.";

export interface ShieldSnippet {
  label: string;
  code: string;
  note?: string;
}

export interface ShieldSection {
  id: string;
  title: string;
  description: string;
  snippets: ShieldSnippet[];
}

export interface ShieldLayer {
  name: string;
  summary: string;
  detects: string[];
}

// The three scanning layers, described (no execution).
export const SHIELD_LAYERS: ShieldLayer[] = [
  {
    name: "Layer 1 — Static code analysis",
    summary: "Scans source files without running anything.",
    detects: [
      "Secrets & API keys — 66 detectors (AWS, Stripe, OpenAI, Supabase, Firebase, Twilio, +60)",
      "Injection sinks — XSS (dangerouslySetInnerHTML/innerHTML), SQLi, eval, exec, SSRF",
      "Missing auth guards — unprotected routes, missing middleware, IDOR-prone patterns",
      "Supply-chain risks — lifecycle scripts, wildcard versions, missing lockfile",
      "Misconfigurations — CORS wildcards, prod source maps, disabled RLS, weak Firebase rules",
      "AI security — prompt injection, LLM output rendered as HTML, tool calls without approval",
    ],
  },
  {
    name: "Layer 2 — Runtime scanner (Playwright)",
    summary: "Spins up a real browser, crawls the app, and probes it safely.",
    detects: [
      "Missing security headers — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy",
      "Insecure cookies — missing HttpOnly/Secure/SameSite, JWT in cookies, long expiry",
      "CORS misconfigs — reflected origins, wildcard + credentials, dev origins in prod",
      "Open redirects — tests 7 common redirect params (next, returnUrl, callbackUrl, …)",
      "Exposed sensitive files — .env, .git/config, swagger.json, package.json, +11",
      "Reflected input — harmless marker injection (HTML/attribute/script/JSON reflection)",
    ],
  },
  {
    name: "Layer 3 — Auth / access-control scanner",
    summary: "Makes real authenticated requests to find broken access control.",
    detects: [
      "Anonymous route access — protected routes reachable without authentication",
      "Vertical privilege escalation — regular user reaching admin-only routes",
      "Horizontal IDOR — UserA reading UserB's resources",
      "Tenant boundary issues — cross-org resource access via predictable IDs",
    ],
  },
];

export const SHIELD_SECTIONS: ShieldSection[] = [
  {
    id: "quick-start",
    title: "Quick start",
    description: "No install required. Node ≥ 18.",
    snippets: [
      { label: "Scan the current directory", code: "npx cybermat scan ." },
    ],
  },
  {
    id: "install",
    title: "Install globally",
    description: "Install the CLI once, then scan any project.",
    snippets: [
      { label: "Install", code: "npm install -g cybermat" },
      { label: "Scan a project", code: "cd your-project\ncybermat scan ." },
    ],
  },
  {
    id: "build-from-source",
    title: "Build from source",
    description: "Clone the repo and build the CLI (pnpm workspace, Node ≥ 18).",
    snippets: [
      {
        label: "Clone + build",
        code:
          "git clone https://github.com/Martysunshine/cybermat-shield.git\n" +
          "cd cybermat-shield\n" +
          "pnpm install && pnpm build",
      },
      {
        label: "Run against the bundled vulnerable app",
        code: "node packages/cli/dist/index.js scan examples/vulnerable-next-app",
      },
    ],
  },
  {
    id: "static",
    title: "Static scanning",
    description: "Scan a directory; add output formats and CI gates as needed.",
    snippets: [
      { label: "Scan a project directory", code: "cybermat scan <path>" },
      { label: "Also output SARIF (GitHub Code Scanning)", code: "cybermat scan <path> --sarif" },
      { label: "Also output a Markdown report", code: "cybermat scan <path> --markdown" },
      { label: "Fail the build on HIGH or above", code: "cybermat scan <path> --fail-on high" },
      { label: "CI mode — exit 5 if new vs baseline", code: "cybermat scan <path> --ci" },
    ],
  },
  {
    id: "runtime",
    title: "Runtime scanning",
    description: "Crawl and probe a live app in a real browser.",
    snippets: [
      { label: "Crawl + probe a live app", code: "cybermat scan-runtime <url>" },
      { label: "Limit pages crawled", code: "cybermat scan-runtime <url> --max-pages 10" },
    ],
  },
  {
    id: "auth",
    title: "Auth / access-control scanning",
    description:
      "The auth scanner needs real session cookies for your test accounts. Sessions reset on dev-server hot-reload, so re-run setup in the same command chain.",
    snippets: [
      { label: "Create an auth config template", code: "cybermat auth init" },
      { label: "Validate auth profiles", code: "cybermat auth test-config" },
      { label: "Run access-control tests", code: "cybermat scan-auth <url>" },
      {
        label: "Refresh sessions + scan (run together)",
        code:
          "npx tsx --tsconfig scripts/tsconfig.json scripts/setup-auth-profiles.ts && \\\n" +
          "node packages/cli/dist/index.js scan-auth http://localhost:3000",
        note: "The example app uses in-memory sessions — they reset on restart/hot-reload.",
      },
    ],
  },
  {
    id: "rules",
    title: "Rules (120+)",
    description: "Every finding maps to an OWASP Top 10:2025 category, a CWE, and a remediation.",
    snippets: [
      { label: "List all rules", code: "cybermat rules list" },
      { label: "Filter by OWASP category", code: "cybermat rules list --owasp A01" },
      { label: "Filter by engine", code: "cybermat rules list --engine secrets" },
      { label: "Show full rule detail + examples", code: "cybermat rules show <id>" },
      { label: "Generate docs/rules.md", code: "cybermat rules docs" },
    ],
  },
  {
    id: "setup",
    title: "Project setup & baseline",
    description: "Create config, verify the environment, and diff against a snapshot.",
    snippets: [
      { label: "Create .cybermatignore + cybermat.config.json", code: "cybermat init" },
      { label: "Check Node, pnpm, Playwright, config", code: "cybermat doctor" },
      { label: "Validate cybermat.config.json", code: "cybermat config validate" },
      { label: "Snapshot current findings", code: "cybermat baseline create" },
      { label: "Show new / fixed / existing vs snapshot", code: "cybermat baseline compare" },
    ],
  },
  {
    id: "config",
    title: "Configuration",
    description: "Run cybermat init to create cybermat.config.json, then tune it.",
    snippets: [
      {
        label: "cybermat.config.json",
        code: `{
  "version": 1,
  "failOn": "high",
  "rules": {
    "disabled": ["secrets/generic-api-key"],
    "severityOverrides": {
      "supply-chain/wildcard-dependency": "high"
    }
  },
  "scan": {
    "maxFileSizeKb": 512,
    "skipDirs": ["node_modules", ".next", "dist"]
  },
  "runtime": {
    "maxPages": 20,
    "maxDepth": 3,
    "requestDelayMs": 150
  }
}`,
      },
    ],
  },
];
