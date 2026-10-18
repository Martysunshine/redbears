<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/expand -->
---
functions:
  file-read:
  - binary: false
    code: |-
      expand /path/to/input-file
    comment: |-
      The read file content is corrupted by replacing tabs with spaces.
    contexts:
      sudo:
      suid:
      unprivileged:
...
