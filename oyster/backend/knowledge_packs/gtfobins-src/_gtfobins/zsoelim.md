<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/zsoelim -->
---
functions:
  file-read:
  - binary: false
    code: |-
      zsoelim /path/to/input-file
    comment: |-
      The content is actually parsed and corrupted by the command.
    contexts:
      sudo:
      suid:
      unprivileged:
...
