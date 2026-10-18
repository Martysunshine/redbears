<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/mutt -->
---
functions:
  file-read:
  - binary: false
    code: |-
      mutt -F /path/to/input-file
    comment: |-
      The file is leaked as error messages.
    contexts:
      sudo:
      unprivileged:
...
