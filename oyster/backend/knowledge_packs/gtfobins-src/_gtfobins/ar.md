<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ar -->
---
functions:
  file-read:
  - code: |-
      ar r /path/to/output-file /path/to/input-file
      ar p /path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
