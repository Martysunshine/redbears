<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/last -->
---
functions:
  file-read:
  - code: |-
      last -a -f /path/to/input-file
    comment: |-
      The output might be corrupted or incomplete if the file does not follow the expected database format.
    contexts:
      sudo:
      suid:
      unprivileged:
...
