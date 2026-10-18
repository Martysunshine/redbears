<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/nm -->
---
functions:
  file-read:
  - binary: false
    code: |-
      nm /path/to/input-file
    comment: |-
      The file content is treated as command line options and disclosed through error messages.
    contexts:
      sudo:
      suid:
      unprivileged:
...
