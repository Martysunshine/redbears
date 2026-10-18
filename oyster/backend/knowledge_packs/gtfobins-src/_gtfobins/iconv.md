<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/iconv -->
---
comment: |-
  The `8859_1` encoding is used as it accepts any single-byte sequence, thus it allows to read/write arbitrary files. Other encoding combinations may corrupt the result.
functions:
  file-read:
  - code: |-
      iconv -f 8859_1 -t 8859_1 /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - code: |-
      echo DATA | iconv -f 8859_1 -t 8859_1 -o /path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
