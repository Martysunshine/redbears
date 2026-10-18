<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/dig -->
---
functions:
  file-read:
  - code: |-
      dig -f /path/to/input-file
    comment: |-
      Each input line is treated as a lookup query for the `dig` command and the output is corrupted with the result or errors of the operation.
    contexts:
      sudo:
      suid:
      unprivileged:
...
