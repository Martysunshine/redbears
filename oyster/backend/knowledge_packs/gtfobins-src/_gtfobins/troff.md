<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/troff -->
---
functions:
  file-read:
  - binary: false
    code: |-
      troff /path/to/input-file
    comment: |-
      The file is typeset but text is still readable in the output, alternatively the output can be read with `man -l`.
    contexts:
      sudo:
      suid:
      unprivileged:
...
