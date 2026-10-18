<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/yelp -->
---
functions:
  file-read:
  - code: |-
      yelp man:/path/to/input-file
    comment: |-
      This spawns a graphical window containing the file content somehow corrupted by word wrapping.
    contexts:
      sudo:
      unprivileged:
...
