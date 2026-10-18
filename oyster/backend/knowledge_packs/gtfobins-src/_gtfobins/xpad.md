<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/xpad -->
---
comment: |-
  This requires a running X server.
functions:
  file-read:
  - code: |-
      xpad -f /path/to/input-file
    comment: |-
      The file is displayed in a graphical window.
    contexts:
      sudo:
      suid:
      unprivileged:
...
