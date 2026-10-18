<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/eb -->
---
comment: |-
  For this to work the target must be connected to an AWS instance via EB CLI.
functions:
  inherit:
  - code: |-
      eb logs
    contexts:
      sudo:
      unprivileged:
    from: journalctl
...
