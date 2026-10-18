<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/LDAPSearch-NoCreds.md -->
---
description: |
  ldapsearch is a Linux based tool that opens a connection to an LDAP server, binds, and performs a search using specified parameters. The following command will attempt to find sensitive information (such as leaked creds), by querying all LDAP objects, essentially dumping all the data that an anonymous user can access.

  Command Reference:

  	Domain: test.local

command: |
  ldapsearch -LLL -x -H ldap://test.local -b'' -s base '(objectclass=\*)'
items:
  - No_Creds
services:
  - LDAP
OS:
  - Linux
attack_types:
  - Enumeration
references:
  - https://linux.die.net/man/1/ldapsearch
---
