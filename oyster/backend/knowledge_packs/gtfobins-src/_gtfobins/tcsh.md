<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/tcsh -->
---
functions:
  file-write:
  - code: |-
      tcsh -c 'echo DATA >/path/to/output-file'
    contexts:
      sudo:
      suid:
        code: |-
          tcsh -bc 'echo DATA >/path/to/output-file'
      unprivileged:
  shell:
  - code: |-
      tcsh
    contexts:
      sudo:
      suid:
        code: |-
          tcsh -b
      unprivileged:
...
