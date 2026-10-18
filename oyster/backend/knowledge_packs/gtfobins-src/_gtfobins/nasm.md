<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/nasm -->
---
functions:
  file-read:
  - code: |-
      nasm -@ /path/to/input-file
    comment: |-
      The file content is treated as command line options and disclosed throught error messages.
    contexts:
      sudo:
      suid:
      unprivileged:
...
