<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/tee -->
---
functions:
  file-write:
  - code: |-
      echo DATA | tee /path/to/output-file
    comment: |-
      Use `-a` to append data to exising files.
    contexts:
      sudo:
      suid:
      unprivileged:
...
