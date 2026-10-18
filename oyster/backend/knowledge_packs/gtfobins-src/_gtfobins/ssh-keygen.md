<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ssh-keygen -->
---
functions:
  library-load:
  - code: |-
      ssh-keygen -D /path/to/lib.so
    comment: |-
      The shared library must contain the `void C_GetFunctionList() {}` function.
    contexts:
      sudo:
      suid:
      unprivileged:
...
