<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/lwp-request -->
---
functions:
  file-read:
  - code: |-
      lwp-request file:///path/to/input-file
    contexts:
      sudo:
      unprivileged:
...
