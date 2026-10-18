<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/RPCClient-Anonymous.md -->
---
description: |
  rpcclient is a tool used for executing client side MS-RPC functions to manage Windows NT clients from Unix workstatios. From an offensive security standpoint, it can be used to enumerate users, groups, and other potentially sensitive information. The following command attempt to connect to the NetBIOS server anonymously, in order to enumerate using MS-RPC available commands/functions.

  Command Reference:

  	Target IP: 10.10.10.1

command: |
  rpcclient -U '' -N 10.10.10.1
items:
  - No_Creds
services:
  - RPC
OS:
  - Linux
attack_types:
  - Enumeration
references:
  - https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html
  - https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-windows-domains-using-rpcclient-through-socksproxy-bypassing-command-line-logging
---
