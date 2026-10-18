<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/msgcat -->
---
functions:
  file-read:
  - binary: false
    code: |-
      msgcat -P /path/to/input-file
    comment: |-
      The file is parsed and displayed as a Java `.properties` file.
    contexts:
      sudo:
      suid:
      unprivileged:
...
