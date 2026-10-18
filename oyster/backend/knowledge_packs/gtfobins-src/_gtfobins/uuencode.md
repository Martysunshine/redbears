<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/uuencode -->
---
functions:
  file-read:
  - binary: false
    code: |-
      uuencode /path/to/input-file /dev/stdout | uudecode
    contexts:
      sudo:
      suid:
      unprivileged:
...
