<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/dd -->
---
functions:
  file-read:
  - code: |-
      dd if=/path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - code: |-
      echo DATA | dd of=/path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
