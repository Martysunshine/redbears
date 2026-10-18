<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/elvish -->
---
functions:
  file-read:
  - code: |-
      elvish -c 'print (slurp </path/to/input-file)'
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - code: |-
      elvish -c 'print DATA >/path/to/output-file'
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      elvish
    contexts:
      sudo:
      suid:
      unprivileged:
...
