<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/zcat -->
---
functions:
  file-read:
  - code: |-
      zcat -f /path/to/input-file
    contexts:
      sudo:
      unprivileged:
...
