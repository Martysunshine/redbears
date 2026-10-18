<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/iftop -->
---
functions:
  shell:
  - code: |-
      iftop
      !/bin/sh
    comment: |-
      This requires the privilege to capture on some device (specify with `-i` if needed).
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
    version: |-
      0.17
...
