<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/fmt -->
---
functions:
  file-read:
  - binary: false
    code: |-
      fmt -pNON_EXISTING_PREFIX /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
    version: |-
      GNU
  - binary: false
    code: |-
      fmt -999 /path/to/input-file
    comment: |-
      This corrupts the output by wrapping very long lines at the given width (`999`).
    contexts:
      sudo:
      suid:
      unprivileged:
...
