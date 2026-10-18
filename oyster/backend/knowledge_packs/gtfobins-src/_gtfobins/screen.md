<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/screen -->
---
functions:
  file-write:
  - binary: false
    code: |-
      screen -L -Logfile /path/to/output-file echo DATA
    comment: |-
      Data is appended to the file and `\n` is converted to `\r\n`.
    contexts:
      sudo:
      unprivileged:
    version: |-
      4.06.02
  - binary: false
    code: |-
      screen -L /path/to/output-file echo DATA
    comment: |-
      Data is appended to the file and `\n` is converted to `\r\n`.
    contexts:
      sudo:
      unprivileged:
    version: |-
      4.05.00
  shell:
  - code: |-
      screen
    contexts:
      sudo:
      unprivileged:
...
