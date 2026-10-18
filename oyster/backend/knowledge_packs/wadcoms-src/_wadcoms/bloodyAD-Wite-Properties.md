<!-- source: https://github.com/WADComs/WADComs.github.io/blob/31283f1532ff1b1c9c8e524bacb0fbc6e251429b/_wadcoms/bloodyAD-Wite-Properties.md -->
---
description: |
  BloodyAD can be used to set, write and delete properties of objects in AD. Given a user:pass, you can use bloodyAD to which objects and what properties of
  those objects are writeable to the user:pass given. Thus if you use -u john -p john, this command will show you what objects and properties
  can john write to

  Command Reference:
    Target IP: 10.10.10.1

  	Domain: test.local

    Username: john

  	Password: password123
command: |
  bloodyAD --host 10.10.10.1 -d test.local -u john -p password123 -d test.local get writable --detail
items:
  - Username
  - Password
attack_types:
  - Enumeration
OS:
  - Linux

references:
  - https://github.com/CravateRouge/bloodyAD
  - https://adminions.ca/books/active-directory-enumeration-and-exploitation/page/bloodyad

---



