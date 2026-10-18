<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/rev -->
---
functions:
  file-read:
  - binary: false
    code: |-
      rev /path/to/input-file | rev
    contexts:
      sudo:
      suid:
      unprivileged:
...
