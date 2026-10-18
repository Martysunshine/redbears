<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/dash -->
---
functions:
  file-write:
  - code: |-
      dash -c 'echo DATA >/path/to/output-file'
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      dash
    contexts:
      sudo:
      suid:
      unprivileged:
...
