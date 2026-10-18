<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/gimp -->
---
functions:
  inherit:
  - code: |-
      gimp -idf --batch-interpreter=python-fu-eval -b '...'
    comment: |-
      This allows to run Python code (`...`). It hangs afterwards and can be terminated by pressing `Ctrl-C`.
    contexts:
      sudo:
      unprivileged:
    from: python
...
