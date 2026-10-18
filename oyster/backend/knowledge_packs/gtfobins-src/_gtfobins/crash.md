<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/crash -->
---
functions:
  command:
  - code: |-
      CRASHPAGER=/path/to/command crash -h
    contexts:
      sudo:
      unprivileged:
  inherit:
  - code: |-
      crash -h
    contexts:
      sudo:
      suid:
      unprivileged:
    from: less
...
