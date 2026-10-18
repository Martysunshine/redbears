<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pandoc -->
---
functions:
  file-read:
  - binary: false
    code: |-
      pandoc -t plain /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - binary: false
    code: |-
      echo DATA | pandoc -t plain -o /path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
  inherit:
  - code: |-
      echo '...' >/path/to/temp-file
      pandoc -L /path/to/temp-file /dev/null
    comment: |-
      This allows to run Lua code (`...`).
    contexts:
      sudo:
      suid:
      unprivileged:
    from: lua
...
