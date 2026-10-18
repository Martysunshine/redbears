<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/basenc -->
---
functions:
  file-read:
  - code: |-
      basenc --base64 /path/to/input-file | basenc -d --base64
    contexts:
      sudo:
      suid:
      unprivileged:
...
