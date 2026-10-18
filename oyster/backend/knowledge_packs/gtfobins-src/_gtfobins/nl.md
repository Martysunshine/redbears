<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/nl -->
---
functions:
  file-read:
  - binary: false
    code: |-
      nl -bn -w1 -s '' /path/to/input-file
    comment: |-
      The read file content is corrupted by a leading space added to each line.
    contexts:
      sudo:
      suid:
      unprivileged:
...
