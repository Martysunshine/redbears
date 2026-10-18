<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/shuf -->
---
functions:
  file-read:
  - code: |-
      shuf -z /path/to/input-file
    comment: |-
      The read file content is corrupted by randomizing the order of NUL terminated strings.
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - code: |-
      shuf -e DATA -o /path/to/output-file
    comment: |-
      The written file content is corrupted by adding a newline.
    contexts:
      sudo:
      suid:
      unprivileged:
...
