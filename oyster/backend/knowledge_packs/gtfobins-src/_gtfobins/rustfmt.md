<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/rustfmt -->
---
functions:
  file-read:
  - binary: false
    code: |-
      rustfmt /path/to/input-file
    comment: |-
      Partial content is displayed as error messages.
    contexts:
      sudo:
      unprivileged:
...
