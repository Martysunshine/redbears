<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/gzip -->
---
comment: |-
  There are also a number of other utilities that rely on `gzip` under the hood, e.g., `zless`, `zcat`, `gunzip`, etc. Besides having similar features, they also allow privileged reads if `gzip` itself is SUID.
functions:
  file-read:
  - code: |-
      gzip -c /path/to/input-file | gzip -d
    contexts:
      capabilities:
        list:
        - CAP_DAC_OVERRIDE
      sudo:
      suid:
      unprivileged:
...
