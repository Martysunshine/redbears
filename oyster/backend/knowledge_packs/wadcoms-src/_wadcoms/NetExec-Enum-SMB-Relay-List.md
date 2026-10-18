<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/NetExec-Enum-SMB-Relay-List.md -->
---
description: |
  "NetExec (a.k.a nxc) is a network service exploitation tool that helps automate assessing the security of large networks." - https://www.netexec.wiki/. The following command will enumerate a list of SMB hosts with signing not enforced, allowing you to relay credentials to them using ntlmrelayx.py.

  Command Reference:

  	SMB Hosts: smb_hosts.txt

command: |
  nxc smb smb_host.txt --gen-relay-list output.txt
items:
  - No_Creds
services:
  - SMB
attack_types:
  - Enumeration
OS:
  - Linux
references:
  - https://github.com/Pennyw0rth/NetExec
  - https://www.netexec.wiki/
---
