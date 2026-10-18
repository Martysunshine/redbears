<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/lualatex -->
---
functions:
  inherit:
  - code: |-
      lualatex -shell-escape '\directlua{...}\end'
    comment: |-
      This allows to run Lua code (`...`).
    contexts:
      sudo:
      suid:
      unprivileged:
    from: lua
...
