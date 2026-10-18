<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/Seatbelt.md -->
---
description: |
  Seatbelt.exe is part of the GhostPack suite of tools that will perform a lot of "safety checks" on the Windows host and collect system data that could be useful for potential privilege escalation or persistence methods. The following command will run all checks on the system and store the output in a file (WARNING: will collect a lot of data. remove `-full` for less output).

  Command Reference:

  	Run all checks: -group=all

  	Output File: output.txt

command: |
  Seatbelt.exe -group=all -full > output.txt
items:
  - Shell
OS:
  - Windows
attack_types:
  - PrivEsc
  - Persistence
references:
  - https://github.com/GhostPack/Seatbelt
  - https://www.harmj0y.net/blog/redteaming/ghostpack/
---
