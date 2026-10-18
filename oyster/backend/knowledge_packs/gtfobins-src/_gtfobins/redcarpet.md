<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/redcarpet -->
---
functions:
  file-read:
  - binary: false
    code: |-
      redcarpet /path/to/input-file
    comment: |-
      The file is actually parsed as a Markdown file.
    contexts:
      sudo:
      unprivileged:
...
