<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/cupsfilter -->
---
functions:
  file-read:
  - code: |-
      cupsfilter -i application/octet-stream -m application/octet-stream /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
