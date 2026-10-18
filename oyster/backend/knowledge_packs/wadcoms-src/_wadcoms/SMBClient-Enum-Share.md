<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/SMBClient-Enum-Share.md -->
---
description: |
  Smbclient is a tool used to communicate with SMB servers. The following command will connect to an SMB share `C$` using valid credentials.

  Command Reference:

  	Target IP: 10.10.10.1

  	Domain: test.local

  	SMB Share: C$

  	Username: john

  	Password: password123

command: |
  smbclient \\\\test.local\\C$ -I 10.10.10.1 -U john password123
items:
  - Username
  - Password
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
