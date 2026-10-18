<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/SMBMap-Enum-Share-Anonymous.md -->
---
description: |
  SMBMap is a tool used to enumerate SMB share drives, including listing share drive permissions, share contents, upload/download functionality, file name enumeration, and remote command execution. The following command will enumerate a list of SMB hosts for accessible SMB shares, both local and mapped drives, without credentials (null session).

  Command Reference:

  	Domain: test.local

  	SMB Hosts: smb-hosts.txt

command: |
  python3 smbmap.py --host-file smb-hosts.txt -d test.local -L
items:
  - No_Creds
services:
  - SMB
OS:
  - Linux
  - Windows
attack_types:
  - Enumeration
references:
  - https://github.com/ShawnDEvans/smbmap
  - https://www.nopsec.com/blog/smbmap-wield-it-like-the-creator/
---
