<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/shred -->
---
functions:
  file-write:
  - code: |-
      shred -u /path/to/output-file
    comment: |-
      This actually deletes the chosen file.
    contexts:
      sudo:
      suid:
      unprivileged:
...
