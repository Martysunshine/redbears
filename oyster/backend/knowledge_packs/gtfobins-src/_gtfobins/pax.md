<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pax -->
---
functions:
  file-read:
  - code: |-
      pax -w /path/to/input-file | tar -xO
    contexts:
      sudo:
      suid:
      unprivileged:
...
