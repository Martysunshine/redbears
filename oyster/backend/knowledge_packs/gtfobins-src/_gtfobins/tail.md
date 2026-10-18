<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/tail -->
---
functions:
  file-read:
  - code: |-
      tail -c+0 /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
