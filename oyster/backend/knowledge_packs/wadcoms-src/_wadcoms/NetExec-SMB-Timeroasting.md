<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/NetExec-SMB-Timeroasting.md -->
---
description: |
  NetExec (formerly CrackMapExec) performs a Timeroasting attack via the SMB service.
  This command targets the remote Windows host and abuses the Kerberos protocol by 
  manipulating ticket lifetimes or requesting renewable service tickets. 
  It can help attackers obtain long-lived Kerberos tickets for offline cracking 
  or later lateral movement.

  Command Reference:

  	Target IP: 10.10.10.1
  	Module: timeroast

command: |
  nxc smb 10.10.10.1 -M timeroast
items:
  - Hash
  - Username
services:
  - SMB
OS:
  - Linux
  - Windows
attack_types:
  - Credential Access
  - Timeroasting
references:
  - https://github.com/Pennyw0rth/NetExec
  - https://cybersecurity.bureauveritas.com/blog/timeroasting-attacking-trust-accounts-in-active-directory
---
