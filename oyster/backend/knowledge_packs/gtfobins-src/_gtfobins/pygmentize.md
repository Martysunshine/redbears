<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pygmentize -->
---
functions:
  file-read:
  - binary: false
    code: |-
      pygmentize -l text /path/to/input-file
    contexts:
      sudo:
      unprivileged:
...
