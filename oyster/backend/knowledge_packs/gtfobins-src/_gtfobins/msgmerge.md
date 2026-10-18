<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/msgmerge -->
---
functions:
  file-read:
  - binary: false
    code: |-
      msgmerge -P /path/to/input-file /dev/null
    comment: |-
      The file is parsed and displayed as a Java `.properties` file.
    contexts:
      sudo:
      suid:
      unprivileged:
...
