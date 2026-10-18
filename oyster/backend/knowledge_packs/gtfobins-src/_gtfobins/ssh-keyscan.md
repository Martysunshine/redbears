<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ssh-keyscan -->
---
functions:
  file-read:
  - code: |-
      ssh-keyscan -f /path/to/input-file
    comment: |-
      The file content is actually parsed so only a part of each line is returned as a part of an error message.
    contexts:
      sudo:
      suid:
      unprivileged:
...
