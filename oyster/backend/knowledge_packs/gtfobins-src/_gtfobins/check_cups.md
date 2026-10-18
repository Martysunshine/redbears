<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/check_cups -->
---
comment: |-
  This is the `check_cups` Nagios plugin, available e.g. in `/usr/lib/nagios/plugins/`.
functions:
  file-read:
  - binary: false
    code: |-
      check_cups --extra-opts=@/path/to/input-file
    comment: |-
      The read file content is limited to the first line.
    contexts:
      sudo:
      unprivileged:
...
