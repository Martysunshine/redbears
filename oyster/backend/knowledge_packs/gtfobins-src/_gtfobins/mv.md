<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/mv -->
---
functions:
  file-write:
  - code: |-
      echo DATA >/path/to/temp-file
      mv /path/to/temp-file /path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
  privilege-escalation:
  - code: |-
      mv /path/to/input-file /path/to/output-file
    comment: |-
      This can be used to move and then read or write files from a restricted file systems or with elevated privileges.
    contexts:
      sudo:
      suid:
...
