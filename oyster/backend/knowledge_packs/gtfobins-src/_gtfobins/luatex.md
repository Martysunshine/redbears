<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/luatex -->
---
functions:
  inherit:
  - code: |-
      luatex -shell-escape '\directlua{...}\end'
    comment: |-
      This allows to run Lua code (`...`).
    contexts:
      sudo:
      suid:
      unprivileged:
    from: lua
...
