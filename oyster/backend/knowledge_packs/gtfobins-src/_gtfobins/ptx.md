<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ptx -->
---
comment: |-
  While the program is capable of reading the file, it outputs a "permuted index" of its content, thus altering it. Adjusting the options could yield more readable outputs.
functions:
  file-read:
  - binary: false
    code: |-
      ptx -w 999 /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
