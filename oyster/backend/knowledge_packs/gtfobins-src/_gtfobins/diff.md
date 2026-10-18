<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/diff -->
---
functions:
  file-read:
  - binary: false
    code: |-
      diff --line-format=%L /dev/null /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
  - code: |-
      diff --recursive /path/to/empty-dir /path/to/input-dir/
    comment: |-
      This lists the content of a directory. `/path/to/empty-dir` can be any directory, but for convenience it is better to use an empty directory to avoid noise output.
    contexts:
      sudo:
      suid:
      unprivileged:
...
