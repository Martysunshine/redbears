<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/bbot -->
---
functions:
  file-read:
  - binary: false
    code: |-
      bbot -d -cy /path/to/input-file
    comment: |-
      The file is displayed in the debug log.
    contexts:
      sudo:
      unprivileged:
...
