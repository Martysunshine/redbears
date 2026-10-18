<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/Impacket-LookUpSID.md -->
---
description: |
  Impacket's lookupsid.py performs bruteforcing of Windows SID's to identify users/groups on the remote target.

  Command Reference:

  	Target IP: 10.10.10.1

  	Domain: test.local

  	Username: john

  	Password: password123

command: |
  python3 lookupsid.py test.local/john:password123@10.10.10.1
items:
  - Password
  - Username
services:
  - RPC
OS:
  - Linux
  - Windows
attack_types:
  - Enumeration
references:
  - https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py
  - https://www.puckiestyle.nl/impacket/
---
