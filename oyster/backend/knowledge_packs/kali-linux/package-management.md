# Kali Linux — Package Management and Metapackages

*Original operator summary. Authoritative source: Kali Linux Documentation — https://www.kali.org/docs/general-use/metapackages/ (OffSec).*

## APT basics

Kali uses Debian's APT. Core commands:

- `sudo apt update` — refresh the package index (do this first).
- `sudo apt full-upgrade` — upgrade everything, including dependency changes (preferred on a rolling release over plain `upgrade`).
- `sudo apt install <pkg>` — install a tool.
- `apt search <term>` / `apt show <pkg>` — find and inspect packages.
- `sudo apt autoremove --purge` — remove unused dependencies and config.

Only the official Kali repository should be enabled in `/etc/apt/sources.list`. Adding random third-party repos is a common way to break a rolling system or introduce untrusted binaries.

## Metapackages (tool bundles)

Kali groups tools into **metapackages** so you install a role, not 300 individual tools:

- `kali-linux-headless` — default CLI toolset, no GUI.
- `kali-linux-default` — the standard desktop install set.
- `kali-linux-large` — a broad superset of tools.
- `kali-linux-everything` — essentially all packaged tools (large download).
- **Role packs**: `kali-tools-web`, `kali-tools-wireless`, `kali-tools-passwords`, `kali-tools-information-gathering`, `kali-tools-exploitation`, `kali-tools-forensics`, `kali-tools-post-exploitation`, `kali-tools-rfid`, and more.

Install only the role you need for the engagement to keep the attack surface and disk footprint small, e.g. `sudo apt install -y kali-tools-web`.

List a metapackage's contents before installing: `apt show kali-tools-web`.

## Keeping tools current

- On a rolling release, `apt update && apt full-upgrade` is the update path — there are no numbered releases to jump between.
- Snapshot the VM before a large upgrade.
- If a tool is newer upstream than the packaged version, prefer a **pipx / virtualenv / container** install over replacing system packages, so you don't fight APT's dependency resolver.

## Non-APT tooling

- **pipx** for Python security tools that you want isolated (`pipx install <tool>`).
- **Docker** for one-off tools you don't want on the base system.
- Build-from-source only when necessary; record the source and commit for reproducibility and evidence.

## Troubleshooting

- Broken upgrade mid-transaction: `sudo dpkg --configure -a` then `sudo apt -f install`.
- Held/conflicting packages: inspect with `apt-cache policy <pkg>`; avoid pinning unless you understand the consequence on a rolling distro.
- Disk pressure from kernels/caches: `sudo apt autoremove --purge` and `sudo apt clean`.
