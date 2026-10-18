<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/espeak -->
---
functions:
  file-read:
  - binary: false
    code: |-
      espeak -qXf /path/to/input-file
    comment: |-
      The file content appears in the middle of other textual information as phonemes.
    contexts:
      sudo:
      suid:
      unprivileged:
...
