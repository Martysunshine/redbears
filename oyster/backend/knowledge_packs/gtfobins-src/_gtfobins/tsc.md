<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/tsc -->
---
functions:
  file-read:
  - binary: false
    code: |-
      tsc /path/to/input-file.ts
    comment: |-
      Content is leaked as error messages. The file extension must be one of the supported ones, e.g., `.ts`, `.tsx`, etc.
    contexts:
      sudo:
      unprivileged:
  file-write:
  - binary: false
    code: |-
      tsc /path/to/input-file.ts --outFile /path/to/output-file
    comment: |-
      Content is leaked as error messages and written to file. The file extension must be one of the supported ones, e.g., `.ts`, `.tsx`, etc.
    contexts:
      sudo:
      unprivileged:
...
