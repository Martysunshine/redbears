<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/SMBClient-List-Share-PTH.md -->
---
description: |
  Smbclient is a tool used to communicate with SMB servers. The following command will list out all available shares on the target ip using user John hash on test domain.

  Command Reference:

  	Target IP: 10.10.10.1

  	Domain: test.local

  	Username: john

  	Hash: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

command: |
  smbclient -L \\10.10.10.1 -U test.local/john --pw-nt-hash XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
items:
  - Username
  - Hash
services:
  - SMB
OS:
  - Linux
attack_types:
  - Enumeration
references:
  - https://www.samba.org/samba/docs/current/man-html/smbclient.1.html
---
