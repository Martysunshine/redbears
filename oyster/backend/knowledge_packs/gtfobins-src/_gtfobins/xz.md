<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/xz -->
---
functions:
  file-read:
  - code: |-
      xz -c /path/to/input-file | xz -d
    contexts:
      sudo:
      suid:
      unprivileged:
...
