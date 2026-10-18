<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/bc -->
---
functions:
  file-read:
  - code: |-
      bc -s /path/to/input-file
      quit
    comment: |-
      The file content is actually parsed and appears as error messages.
    contexts:
      sudo:
      suid:
      unprivileged:
...
