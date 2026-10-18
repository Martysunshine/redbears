<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/xmodmap -->
---
comment: |-
  This requires a running X server.
functions:
  file-read:
  - binary: false
    code: |-
      xmodmap -v /path/to/input-file
    comment: |-
      The read file content is corrupted by error prints.
    contexts:
      sudo:
      suid:
      unprivileged:
...
