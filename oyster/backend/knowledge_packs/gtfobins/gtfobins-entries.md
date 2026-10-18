# GTFOBins — Structured Binary-Abuse Entries

*Original structured summaries with detection/mitigation authored for Oyster. Canonical data: https://gtfobins.github.io/ — always confirm the exact technique for the target's binary version. Read-only knowledge; active use requires an authorized host + approval.*

GTFOBins catalogs how legitimate Unix binaries can be abused. The relevant question during an assessment is: *given a binary I can run as root (SUID) or via `sudo`, can it run an arbitrary command, read/write an arbitrary file, or spawn a shell?* Cross-reference every SUID/`sudo -l` finding here.

---

## find

- **Binary**: `find`
- **Function**: Shell / command execution via the `-exec` action.
- **Prerequisite**: `find` is SUID-root, or runnable via `sudo`.
- **Example (intent)**: use `-exec` to launch a shell that inherits the elevated privileges while "searching".
- **Risk**: Full root shell. High.
- **Detection**: `find` invocations with `-exec ... ;` spawning `sh`/`bash`, especially from SUID context; EDR process-lineage `find → sh`.
- **Mitigation**: Remove the SUID bit; never grant `sudo find`. Use least-privilege wrappers.
- **Source**: https://gtfobins.github.io/gtfobins/find/

## vim / vi

- **Binary**: `vim`
- **Function**: Command execution / shell escape (`:!`, `:py`, `-c`).
- **Prerequisite**: SUID or `sudo vim`.
- **Example (intent)**: drop to a shell from the editor's command mode with inherited privileges.
- **Risk**: Root shell. High.
- **Detection**: Editors spawning shells; child `sh` of `vim`/`vi` under a service or root context.
- **Mitigation**: Don't allow editors via `sudo`; use `sudoedit`/`rvim` (restricted) instead.
- **Source**: https://gtfobins.github.io/gtfobins/vim/

## less / more / man

- **Binary**: `less` (also `more`, `man` which pages through `less`)
- **Function**: Shell escape via the pager's `!` command.
- **Prerequisite**: SUID or `sudo`, and an interactive pager.
- **Example (intent)**: run `!sh` from within the pager.
- **Risk**: Root shell. High.
- **Detection**: Pagers spawning shells; interactive `less`/`man` under automation.
- **Mitigation**: Set `LESSSECURE=1`; avoid paging tools in privileged sudo rules.
- **Source**: https://gtfobins.github.io/gtfobins/less/

## awk / gawk

- **Binary**: `awk`
- **Function**: Command execution via `system()` / `BEGIN{...}`.
- **Prerequisite**: SUID or `sudo awk`.
- **Example (intent)**: use a `BEGIN` block calling `system()` to run a command as root.
- **Risk**: Arbitrary command execution. High.
- **Detection**: `awk` with `system(` in the program text; `awk` spawning `sh`.
- **Mitigation**: Remove SUID; keep interpreters out of sudo rules.
- **Source**: https://gtfobins.github.io/gtfobins/awk/

## tar

- **Binary**: `tar`
- **Function**: Command execution via checkpoint actions (`--checkpoint-action=exec=...`).
- **Prerequisite**: SUID or `sudo tar`; also a classic **wildcard injection** vector when root runs `tar *` in a writable directory.
- **Example (intent)**: craft filenames that `tar`'s option parser treats as flags, triggering an exec action.
- **Risk**: Command execution as root. High.
- **Detection**: `tar` invocations with `--checkpoint`/`--checkpoint-action`; cron jobs running `tar *` in writable dirs.
- **Mitigation**: Quote/anchor paths in scripts (`./`), avoid globbing as root, remove SUID.
- **Source**: https://gtfobins.github.io/gtfobins/tar/

## python / perl / ruby

- **Binary**: interpreters (`python3`, `perl`, `ruby`)
- **Function**: Arbitrary code/shell execution and (with `cap_setuid`) direct UID change.
- **Prerequisite**: SUID interpreter, `sudo`, or a capability like `cap_setuid+ep`.
- **Example (intent)**: call `os.setuid(0)` then `os.system("sh")` when the capability allows.
- **Risk**: Immediate root. Critical when `cap_setuid` is set.
- **Detection**: `getcap` monitoring for interpreters with `cap_setuid`; interpreters spawning shells as root.
- **Mitigation**: Never assign `cap_setuid` to interpreters; remove SUID; audit capabilities with `getcap -r /`.
- **Source**: https://gtfobins.github.io/gtfobins/python/

## nmap (legacy)

- **Binary**: `nmap` (old versions with interactive mode)
- **Function**: Shell via interactive `--interactive` `!sh` (legacy) or `--script` NSE execution.
- **Prerequisite**: SUID or `sudo`, old nmap for interactive mode.
- **Risk**: Root shell / arbitrary NSE. High on legacy systems.
- **Detection**: `nmap --interactive` or unexpected `--script` from privileged context.
- **Mitigation**: Update nmap; never SUID scanning tools.
- **Source**: https://gtfobins.github.io/gtfobins/nmap/

## How to use these entries

For each SUID binary or `sudo -l` entry you find, look up whether it appears here (or on GTFOBins). If it does, you have a concrete escalation primitive **and** a matching detection/mitigation — report all three so the finding is actionable for the defender.
