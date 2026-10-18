<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/fping -->
---
functions:
  file-read:
  - binary: false
    code: |-
      fping -f /path/to/input-file
    comment: |-
      Each line is treated as an hostname and it's leaked as an error message.
    contexts:
      sudo:
      suid:
      unprivileged:
...
