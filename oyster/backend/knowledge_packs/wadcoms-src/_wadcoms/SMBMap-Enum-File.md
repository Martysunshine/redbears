<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/SMBMap-Enum-File.md -->
---
description: |
  SMBMap is a tool used to enumerate SMB share drives, including listing share drive permissions, share contents, upload/download functionality, file name enumeration, and remote command execution. The following command will enumerate a list of SMB hosts for files and filenames containing the keyword 'password'.

  Command Reference:

  	Domain: test.local

  	SMB Hosts: smb-hosts.txt

  	Username: john

  	Password: password123

command: |
  python3 smbmap.py --host-file smb-hosts.txt -u john -p 'password123' -d test.local -F password
items:
  - Username
  - Password
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
