<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/bzip2 -->
---
comment: |-
  There are also a number of other utilities that rely on `bzip2` under the hood, e.g., `bzless`, `bzcat`, `bunzip2`, etc. Besides having similar features, they also allow privileged reads if `bzip2` itself is SUID.
functions:
  file-read:
  - code: |-
      bzip2 -c /path/to/input-file | bzip2 -d
    contexts:
      sudo:
      suid:
      unprivileged:
...
