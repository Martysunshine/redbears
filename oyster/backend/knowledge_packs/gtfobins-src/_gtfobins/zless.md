<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/zless -->
---
functions:
  inherit:
  - code: |-
      zless /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
    from: less
...
