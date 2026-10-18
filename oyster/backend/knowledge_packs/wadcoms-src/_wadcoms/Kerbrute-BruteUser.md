<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/Kerbrute-BruteUser.md -->
---
description: |
  ropnop's kerbrute bruteforces and enumerates valid Active Directory accounts through Kerberos Pre-Authentication. The following command will bruteforce an account against a list of provided passwords given a username.

  Command Reference:

  	Domain: test.local

  	Password List: passwords.txt

  	Username: john
command: |
  kerbrute bruteuser -d test.local passwords.txt john
items:
  - Username
services:
  - Kerberos
OS:
  - Linux
  - Windows
attack_types:
  - Enumeration
references:
  - https://github.com/ropnop/kerbrute
---
