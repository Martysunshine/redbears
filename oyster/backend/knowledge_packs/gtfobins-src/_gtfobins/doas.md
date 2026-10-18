<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/doas -->
---
functions:
  shell:
  - code: |-
      doas -u root /bin/sh
    comment: |-
      The user must be allowed to use `doas`.
    contexts:
      sudo:
      unprivileged:
...
