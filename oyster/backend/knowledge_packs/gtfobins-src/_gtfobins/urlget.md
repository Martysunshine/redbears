<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/urlget -->
---
functions:
  file-read:
  - code: |-
      urlget - /path/to/input-file
    comment: |-
      This is part of `gettext` and usually not in `PATH`, e.g., on Arch it can be found at `/usr/lib/gettext/urlget`.
    contexts:
      sudo:
      suid:
      unprivileged:
...
