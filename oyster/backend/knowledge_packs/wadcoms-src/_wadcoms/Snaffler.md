<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/Snaffler.md -->
---
description: |
  Snaffler is a tool used to enumerate sensitive data (passwords, PII, etc.) from file shares in Active Directory. It searches for interesting files based on file extensions, file names, and file content that's matched against regex. It's also highly configurable, allowing you to add your own regex searches. The following command will enumerate all machines in the domain and search for accessible file shares, checking for interesting files that might have sensitive data.

  Command Reference:

  	Domain: test.local

  	Domain Controller: 10.10.10.1

command: |
  Snaffler.exe -s -o snaffler_output.log -d test.local -c 10.10.10.1
items:
  - Shell
services:
  - SMB
OS:
  - Windows
attack_types:
  - Enumeration
references:
  - https://github.com/SnaffCon/Snaffler
---
