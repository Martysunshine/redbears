<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/cut -->
---
functions:
  file-read:
  - binary: false
    code: |-
      cut -d '' -f1 /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
