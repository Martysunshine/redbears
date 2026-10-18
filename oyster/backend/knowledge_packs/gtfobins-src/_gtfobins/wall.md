<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/wall -->
---
functions:
  file-read:
  - binary: false
    code: |-
      wall --nobanner /path/to/input-file
    comment: |-
      The textual file is dumped on the current TTY (neither to `stdout` nor to `stderr`).
    contexts:
      sudo:
...
