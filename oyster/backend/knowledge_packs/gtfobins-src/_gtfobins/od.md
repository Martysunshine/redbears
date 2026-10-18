<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/od -->
---
functions:
  file-read:
  - code: |-
      od -An -c -w999 /path/to/input-file
    comment: |-
      Three spaces are added before each character in the read file (wrapped at the specified value, i.e., `999`), and non-printable chars are printed as backslash escape sequences.
    contexts:
      sudo:
      suid:
      unprivileged:
...
