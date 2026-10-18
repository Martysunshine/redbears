<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pipx -->
---
functions:
  inherit:
  - code: |-
      echo '...' >/path/to/file.py
      pipx run /path/to/file.py
    comment: |-
      This allows to run Python code (`...`).
    contexts:
      sudo:
      unprivileged:
    from: python
...
