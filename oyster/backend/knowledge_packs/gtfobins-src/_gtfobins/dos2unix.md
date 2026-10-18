<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/dos2unix -->
---
functions:
  file-read:
  - code: |-
      dos2unix -f -O /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - code: |-
      dos2unix -f -n /path/to/input-file /path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
