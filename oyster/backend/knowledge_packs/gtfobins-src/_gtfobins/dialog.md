<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/dialog -->
---
functions:
  file-read:
  - code: |-
      dialog --textbox /path/to/input-file 0 0
    comment: |-
      The file is shown in an interactive TUI dialog.
    contexts:
      sudo:
      suid:
      unprivileged:
...
