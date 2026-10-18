<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/cmp -->
---
functions:
  file-read:
  - binary: false
    code: |-
      cmp /path/to/input-file /dev/zero -b -l
    comment: |-
      Dump the bytes of the input file that are different from the NUL byte in a tabular format.
    contexts:
      sudo:
      suid:
      unprivileged:
...
