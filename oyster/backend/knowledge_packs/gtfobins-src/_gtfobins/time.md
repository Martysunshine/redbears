<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/time -->
---
functions:
  shell:
  - code: |-
      time /bin/sh
    comment: |-
      Note that the shell might have its own builtin `time` implementation, which may behave differently than the binary, which is often located at `/usr/bin/time`.
    contexts:
      sudo:
      suid:
        code: |-
          time /bin/sh -p
        shell: false
      unprivileged:
...
