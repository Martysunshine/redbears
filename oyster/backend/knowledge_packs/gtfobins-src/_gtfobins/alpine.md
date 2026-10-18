<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/alpine -->
---
functions:
  file-read:
  - code: |-
      alpine -F /path/to/input-file
    comment: |-
      The file is displayed in the terminal interface. Other options might be available, for example, by pressing `S` is possible to save the file content elsewhere.
    contexts:
      sudo:
      suid:
      unprivileged:
...
