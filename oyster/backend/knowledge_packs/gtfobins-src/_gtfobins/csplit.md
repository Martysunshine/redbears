<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/csplit -->
---
functions:
  file-read:
  - code: |-
      csplit /path/to/input-file 1
      cat xx01
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - code: |-
      echo DATA >/path/to/temp-file
      csplit -z -b '%doutput-file' /path/to/temp-file 1
    comment: |-
      Writes the data to `xx0output-file` in the current working directory. If needed, a different prefix can be specified with `-f` (instead of `xx`).
    contexts:
      sudo:
      suid:
      unprivileged:
...
