<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/sqlmap -->
---
functions:
  inherit:
  - code: |-
      sqlmap -u 127.0.0.1 --eval='...'
    comment: |-
      This allows to run Python code (`...`).
    contexts:
      sudo:
      unprivileged:
    from: python
...
