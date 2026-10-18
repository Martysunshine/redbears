<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/SharpDump.md -->
---
description: |
  SharpDump.exe is part of the GhostPack suite of tools and is a C# port of PowerSploit's Out-Minidump.ps1. It can dump the process for LSASS or a specific process given it's PID. This dump can then be fed into mimikatz to extract sensitive information. The following command simply dumps the LSASS process.

command: |
  SharpDump.exe
items:
  - Shell
OS:
  - Windows
attack_types:
  - PrivEsc
  - Enumeration
references:
  - https://github.com/GhostPack/SharpDump
  - https://www.harmj0y.net/blog/redteaming/ghostpack/
---
