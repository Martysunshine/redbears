<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/xxd -->
---
functions:
  file-read:
  - code: |-
      xxd /path/to/input-file | xxd -r
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - code: |-
      echo DATA | xxd | xxd -r - /path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
