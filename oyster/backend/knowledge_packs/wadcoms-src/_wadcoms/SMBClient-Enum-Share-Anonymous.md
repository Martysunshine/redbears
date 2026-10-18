<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/SMBClient-Enum-Share-Anonymous.md -->
---
description: |
  Smbclient is a tool used to communicate with SMB servers. The following command will connect to an SMB share `public` using anonymous login.

  Command Reference:

  	Target IP: 10.10.10.1

  	Domain: test.local

  	SMB Share: public

command: |
  smbclient \\\\test.local\\public -I 10.10.10.1 -N
items:
  - No_Creds
services:
  - SMB
OS:
  - Linux
attack_types:
  - Enumeration
references:
  - https://www.samba.org/samba/docs/current/man-html/smbclient.1.html
  - https://www.madirish.net/59
---
