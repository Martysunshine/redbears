<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/chattr -->
---
functions:
  privilege-escalation:
  - code: |-
      chattr +i /path/to/input-file
    comment: |-
      Make the target file immutable.
    contexts:
      sudo:
      suid:
...
