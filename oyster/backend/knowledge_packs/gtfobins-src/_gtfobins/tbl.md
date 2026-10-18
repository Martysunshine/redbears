<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/tbl -->
---
functions:
  file-read:
  - binary: false
    code: |-
      tbl /path/to/input-file
    comment: |-
      The read file content is corrupted by additional text at the beginning.
    contexts:
      sudo:
      suid:
      unprivileged:
...
