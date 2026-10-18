<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/joe -->
---
functions:
  shell:
  - code: |-
      joe
      ^K!/bin/sh
    comment: |-
      The terminal is spawn int the terminal interface.
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
