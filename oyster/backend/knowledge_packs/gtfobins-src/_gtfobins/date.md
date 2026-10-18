<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/date -->
---
functions:
  file-read:
  - binary: false
    code: |-
      date -f /path/to/input-file
    comment: |-
      Each line is corrupted by a prefix string and wrapped inside quotes.
    contexts:
      sudo:
      suid:
      unprivileged:
    version: |-
      GNU
...
