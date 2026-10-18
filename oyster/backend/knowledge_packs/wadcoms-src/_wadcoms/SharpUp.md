<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/SharpUp.md -->
---
description: |
  SharpUp.exe is part of the GhostPack suite of tools and is a C# port of PowerUp that will perform numerous privilege escalation checks. The following command will run all priv esc checks and store the output in a file.

  Command Reference:

  	Output File: output.txt

command: |
  SharpUp.exe > output.txt
items:
  - Shell
OS:
  - Windows
attack_types:
  - PrivEsc
references:
  - https://github.com/GhostPack/SharpUp
  - https://www.harmj0y.net/blog/redteaming/ghostpack/
---
