<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/hexdump -->
---
functions:
  file-read:
  - code: |-
      hd /path/to/input-file
    comment: |-
      The output is actually an hex dump.
    contexts:
      sudo:
      suid:
      unprivileged:
...
