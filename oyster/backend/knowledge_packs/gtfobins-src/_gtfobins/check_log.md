<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/check_log -->
---
comment: |-
  This is the `check_log` Nagios plugin, available e.g. in `/usr/lib/nagios/plugins/`.
functions:
  file-read:
  - code: |-
      check_log -F /path/to/input-file -O /dev/stdout
    contexts:
      sudo:
      unprivileged:
  file-write:
  - code: |-
      check_log -F /path/to/input-file -O /path/to/output-file
    contexts:
      sudo:
      unprivileged:
...
