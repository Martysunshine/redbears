<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ascii85 -->
---
functions:
  file-read:
  - code: |-
      ascii85 /path/to/input-file | ascii85 --decode
    contexts:
      sudo:
      unprivileged:
...
