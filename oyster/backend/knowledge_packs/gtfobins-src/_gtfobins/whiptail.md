<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/whiptail -->
---
functions:
  file-read:
  - binary: false
    code: |-
      whiptail --textbox --scrolltext /path/to/input-file 0 0
    comment: |-
      The file is shown in an interactive TUI dialog made for displaying text, arrows can be used to scroll long content.
    contexts:
      sudo:
      suid:
      unprivileged:
...
