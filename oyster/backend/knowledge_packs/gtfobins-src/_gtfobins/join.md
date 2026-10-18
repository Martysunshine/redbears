<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/join -->
---
functions:
  file-read:
  - binary: false
    code: |-
      join -a 2 /dev/null /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
