<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/wc -->
---
functions:
  file-read:
  - binary: false
    code: |-
      wc --files0-from /path/to/input-file
    comment: |-
      The file content is parsed as a sequence of `\x00` separated paths. On error the file content appears in a message.
    contexts:
      sudo:
      suid:
      unprivileged:
...
