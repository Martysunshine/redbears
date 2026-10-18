<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ghci -->
---
functions:
  shell:
  - code: |-
      ghci
      System.Process.callCommand "/bin/sh"
    contexts:
      sudo:
      unprivileged:
...
