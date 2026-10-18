<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/unexpand -->
---
functions:
  file-read:
  - binary: false
    code: |-
      unexpand -t999 /path/to/input-file
    comment: |-
      Convert sequences of (e.g., `999`) spaces to tab.
    contexts:
      sudo:
      suid:
      unprivileged:
...
