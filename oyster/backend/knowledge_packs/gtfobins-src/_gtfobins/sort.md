<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/sort -->
---
functions:
  file-read:
  - binary: false
    code: |-
      sort -m /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - binary: false
    code: |-
      echo DATA | sort -m -o /path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
