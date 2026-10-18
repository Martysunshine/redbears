<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/env -->
---
functions:
  shell:
  - code: |-
      env /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          env /bin/sh -p
        shell: false
      unprivileged:
...
