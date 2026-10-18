# Kali Linux — Installation and Platforms

*Original operator summary. Authoritative source: Kali Linux Documentation — https://www.kali.org/docs/ (OffSec). Verify commands against the official docs before use.*

## Choosing a platform

Kali is a rolling Debian-derived distribution built for security testing. Pick the deployment that matches the engagement:

- **Bare metal** — maximum performance and hardware access (wireless adapters, USB). Best for wireless/hardware work.
- **Virtual machine (VMware/VirtualBox/UTM/QEMU)** — the default for most testing. Snapshots let you revert to a clean state after each engagement. OffSec publishes prebuilt VM images so you skip installation.
- **Docker** — ephemeral, scriptable tool containers. Ideal for CI or running a single tool without a full desktop.
- **WSL (Windows Subsystem for Linux)** — Kali as a command-line environment inside Windows. Good for note-taking hosts and light tooling; GUI apps need `kali-win-kex`.
- **ARM (Raspberry Pi and similar)** — portable/drop-box implants and low-power labs. Dedicated ARM images per board.
- **Cloud / WSL / mobile (NetHunter)** — situational.

## Installer notes

- Verify the ISO/image **SHA256 and GPG signature** against the values on kali.org before booting — this is the single most important supply-chain step.
- Use **guided partitioning with LUKS full-disk encryption** for any host that leaves a controlled facility; use **encrypted persistence** for live-USB.
- Default credentials on modern Kali are `kali` / `kali`; change them immediately.
- After first boot: `sudo apt update && sudo apt full-upgrade` before installing extra tooling.

## Virtual machines

- Prefer the **prebuilt Kali VM images** to avoid a manual install; import the OVA/VMware bundle.
- Install guest additions/open-vm-tools for clipboard, shared folders, and display scaling.
- Take a **clean baseline snapshot** immediately after setup and after each major tool install so you can roll back to a known-good state — important for evidence integrity.
- Give at least 2 vCPU / 4 GB RAM (8 GB+ for Burp, heavy fuzzing, or cracking).

## Docker

- Pull the official image: `docker pull kalilinux/kali-rolling`.
- It ships minimal; add tools inside the container with `apt update && apt install -y <tool>` or a metapackage.
- Treat containers as **disposable**: mount a host directory for output so results survive `docker rm`.
- Docker gives isolation for a single tool, not a full desktop — combine with `kali-linux-headless` for a scriptable toolset.

## WSL

- Install from the Microsoft Store or `wsl --install -d kali-linux`.
- For a desktop use **Win-KeX** (`sudo apt install -y kali-win-kex`) which provides Window, Seamless, and Enhanced Session modes.
- WSL shares the Windows network stack — useful for pivoting from a Windows testing host, but be aware traffic egresses via the host.

## ARM

- Download the image for your **specific board** (Raspberry Pi models differ); generic images will not boot.
- Flash with a verified tool; expand the filesystem on first boot.
- ARM builds are excellent for portable/remote testing drop-boxes; plan for headless SSH access and encrypted persistence.

## Operational hygiene

- Keep the toolset current (rolling release) but snapshot before large upgrades — a rolling distro can occasionally break a tool mid-engagement.
- Never test from a Kali host against systems that are not in the **written authorized scope**; the presence of a tool is not authorization.
