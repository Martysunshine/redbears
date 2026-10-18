<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/fold -->
---
functions:
  file-read:
  - binary: false
    code: |-
      fold -w999 /path/to/input-file
    comment: |-
      This corrupts the output by wrapping very long lines at the given width (`999`).
    contexts:
      sudo:
      suid:
      unprivileged:
...
