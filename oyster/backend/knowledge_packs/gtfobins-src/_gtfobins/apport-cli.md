<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/apport-cli -->
---
functions:
  inherit:
  - code: |-
      apport-cli -f
      1
      2
      v
    comment: |-
      The terminal interface expects some choices in order to spawn tha pager.
    contexts:
      unprivileged:
    from: less
...
