<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/Rubeus-Kerberoast.md -->
---
description: |
  Rubeus' `kerberoast` module will attempt to fetch Service Principal Names that are associated with normal user accounts. What is returned is a ticket that is encrypted with the user account's password, which can then be bruteforced offline. The following command is run on a Windows machine in the victim domain.

  Command Reference:

  	Output File: hashes.txt

command: |
  Rubeus.exe kerberoast /outfile:hashes.txt
items:
  - Shell
services:
  - Kerberos
OS:
  - Windows
attack_types:
  - Exploitation
  - PrivEsc
references:
  - https://github.com/GhostPack/Rubeus
  - https://github.com/GhostPack/Rubeus#kerberoast
---
