<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/check_statusfile -->
---
comment: |-
  This is the `check_statusfile` Nagios plugin, available e.g. in `/usr/lib/nagios/plugins/`.
functions:
  file-read:
  - code: |-
      check_statusfile /path/to/input-file
    comment: |-
      The read file content is limited to the first line.
    contexts:
      sudo:
      unprivileged:
...
