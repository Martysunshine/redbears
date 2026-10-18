<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/mypy -->
---
functions:
  file-read:
  - binary: false
    code: |-
      mypy /path/to/input-file
    comment: |-
      Partial content is leaked as error messages.
    contexts:
      sudo:
      unprivileged:
  file-write:
  - binary: false
    code: |-
      mypy /path/to/input-file --junit-xml /path/to/output-file
    comment: |-
      Partial content is leaked as error messages inside some XML tags.
    contexts:
      sudo:
      unprivileged:
...
