<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ul -->
---
functions:
  file-read:
  - binary: false
    code: |-
      ul /path/to/input-file
    comment: |-
      The read file content is corrupted by replacing occurrences of `$'\b_'` to terminal sequences and by converting tabs to spaces.
    contexts:
      sudo:
      suid:
      unprivileged:
...
