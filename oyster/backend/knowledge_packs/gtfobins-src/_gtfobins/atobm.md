<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/atobm -->
---
functions:
  file-read:
  - code: |-
      atobm /path/to/input-file
    comment: |-
      Outputs only the first line of the file to standard error without the `-` and `#` characters, this can be customized with the `-c` option, by default is `-c -#`. Content can be retrieved with `awk -F "'" '{printf "%s", $2}'`.
    contexts:
      sudo:
      suid:
      unprivileged:
...
