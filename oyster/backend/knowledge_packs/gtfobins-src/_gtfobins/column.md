<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/column -->
---
functions:
  file-read:
  - binary: false
    code: |-
      column /path/to/input-file
    comment: |-
      This program expects textual data.
    contexts:
      sudo:
      suid:
      unprivileged:
...
