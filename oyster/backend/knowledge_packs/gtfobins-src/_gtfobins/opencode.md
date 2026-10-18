<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/opencode -->
---
functions:
  command:
  - code: |-
      opencode
      ! /path/to/command
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
  inherit:
  - code: |-
      opencode db '...'
    comment: |-
      This allows to run SQLite queries (`...`) provided that `sqlite3` is installed.
    contexts:
      sudo:
      unprivileged:
    from: sqlite3
...
