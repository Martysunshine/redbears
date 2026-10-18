# Linux Privilege Escalation — Methodology Summary

*Original condensed methodology. Techniques popularized by HackTricks — https://book.hacktricks.wiki/ (verify against source). Read-only knowledge: any active use requires an authorized, in-scope target and approval.*

Privilege escalation on Linux is an enumeration problem first. Run an automated checker (LinPEAS, linux-smart-enumeration) *and* verify by hand. Look for a misconfiguration that lets an unprivileged user run something as root.

## Enumeration checklist

- **System & kernel**: `uname -a`, distro version — note the kernel for known local-privesc CVEs (validate the exact version; do not assume).
- **Users & groups**: `id`, `sudo -l`, membership in `docker`, `lxd`, `disk`, `adm`.
- **SUID/SGID binaries**: `find / -perm -4000 -type f 2>/dev/null` — cross-reference against GTFOBins for a binary that spawns a shell.
- **Capabilities**: `getcap -r / 2>/dev/null` — e.g. `cap_setuid` on an interpreter is game over.
- **Cron jobs & timers**: writable scripts or wildcards run by root.
- **Writable files**: world-writable scripts in root's PATH, writable `/etc/passwd`, writable service unit files.
- **Credentials at rest**: history files, config files, `.env`, private keys, database creds.
- **Network & services**: internal services on localhost that may run as root.

## Common escalation vectors (concepts, not payloads)

- **`sudo -l` misconfig** — a program the user may run as root that can execute arbitrary commands or read arbitrary files (map the binary to GTFOBins for the exact technique).
- **SUID binary** — a set-uid-root program with a known shell-spawn or file-read primitive.
- **Writable cron / systemd unit** — inject a command into something root executes on a schedule.
- **PATH hijack** — a root process calls a binary by relative name; place a malicious one earlier in PATH.
- **Capabilities** — `cap_setuid`, `cap_dac_read_search`, etc. grant a subset of root power.
- **Container escapes** — membership in `docker`/`lxd` is effectively root on the host; privileged containers and mounted host paths.

## Discipline

Confirm the primitive, take a screenshot/log as evidence, and **stop at proof** unless the rules of engagement authorize going further. Note the exact detection opportunity (see the MITRE ATT&CK and detection packs) so the finding includes a defensive fix, not just an exploit.
