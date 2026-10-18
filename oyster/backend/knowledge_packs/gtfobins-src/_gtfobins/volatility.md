<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/volatility -->
---
comment: |-
  This allows to run Python code (`...`). Some valid core dump file is required, if not available, can be uploaded to the target.
functions:
  inherit:
  - code: |-
      volatility -f /path/to/core-dump volshell
      ...
    contexts:
      sudo:
      suid:
      unprivileged:
    from: python
...
