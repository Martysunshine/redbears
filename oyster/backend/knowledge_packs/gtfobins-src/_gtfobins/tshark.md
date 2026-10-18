<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/tshark -->
---
functions:
  inherit:
  - code: |-
      echo '...' >/path/to/temp-file
      tshark -Xlua_script:/path/to/temp-file
    comment: |-
      This allows to run Lua code (`...`).
    contexts:
      sudo:
      unprivileged:
    from: lua
...
