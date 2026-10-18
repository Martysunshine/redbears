<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/jtag -->
---
functions:
  shell:
  - code: |-
      jtag --interactive
      shell /bin/sh
    contexts:
      sudo:
      unprivileged:
...
