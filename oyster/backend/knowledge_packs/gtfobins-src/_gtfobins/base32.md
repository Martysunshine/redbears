<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/base32 -->
---
functions:
  file-read:
  - code: |-
      base32 /path/to/input-file | base32 --decode
    contexts:
      sudo:
      suid:
      unprivileged:
...
