<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/comm -->
---
functions:
  file-read:
  - binary: false
    code: |-
      comm /path/to/input-file /dev/null
    comment: |-
      A newline is appended to the file.
    contexts:
      sudo:
      suid:
      unprivileged:
...
