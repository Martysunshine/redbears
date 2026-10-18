<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pdb -->
---
functions:
  inherit:
  - code: |-
      echo '...' >/path/to/temp-file
      pdb /path/to/temp-file
      cont
    comment: |-
      This allows to run Python code (`...`).
    contexts:
      sudo:
      unprivileged:
    from: python
...
