<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/Impacket-SMBClient.md -->
---
description: |
  Impacket's smbclient.py is a generic smbclient, allowing you to list shares and files, rename, upload and download files and create and delete directories.

  Command Reference:

  	Target IP: 10.10.10.1

  	Domain: test.local

  	Username: john

  	Password: password123

command: |
  python3 smbclient.py test.local/john:password123@10.10.10.1
items:
  - Password
  - Username
services:
  - SMB
OS:
  - Linux
  - Windows
attack_types:
  - Enumeration
references:
  - https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py
  - https://www.hackingarticles.in/impacket-guide-smb-msrpc/
---
