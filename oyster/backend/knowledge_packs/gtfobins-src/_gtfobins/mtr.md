<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/mtr -->
---
functions:
  file-read:
  - binary: false
    code: |-
      mtr --raw -F /path/to/input-file
    comment: |-
      The file is actually parsed, thus the content is corrupted by error prints.
    contexts:
      sudo:
      unprivileged:
...
