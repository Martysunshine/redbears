<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/uniq -->
---
functions:
  file-read:
  - binary: false
    code: |-
      uniq /path/to/input-file
    comment: |-
      The read file content is corrupted by squashing multiple adjacent lines.
    contexts:
      sudo:
      suid:
      unprivileged:
...
