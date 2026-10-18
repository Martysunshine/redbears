<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/bee -->
---
functions:
  inherit:
  - code: |-
      bee eval '...'
    comment: |-
      This allows to run PHP code (`...`).

      This must be excuted from the Backdrop CMS root directory (e.g. `/var/www/html`), alternatively use the `--root` option.
    contexts:
      sudo:
      suid:
      unprivileged:
    from: php
...
