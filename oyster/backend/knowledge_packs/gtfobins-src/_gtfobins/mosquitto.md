<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/mosquitto -->
---
functions:
  file-read:
  - code: |-
      mosquitto -c /path/to/input-file
    comment: |-
      The file is actually parsed and the first wrong line (ending with a newline or a null character) is returned in an error message.
    contexts:
      sudo:
      suid:
      unprivileged:
...
