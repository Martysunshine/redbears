<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/w3m -->
---
functions:
  file-read:
  - binary: false
    code: |-
      w3m -dump /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
