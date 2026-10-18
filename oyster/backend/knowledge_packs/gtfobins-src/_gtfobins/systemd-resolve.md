<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/systemd-resolve -->
---
functions:
  inherit:
  - code: |-
      systemd-resolve --status
    contexts:
      sudo:
    from: less
...
