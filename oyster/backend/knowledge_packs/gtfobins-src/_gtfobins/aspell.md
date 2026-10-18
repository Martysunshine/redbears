<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/aspell -->
---
functions:
  file-read:
  - binary: false
    code: |-
      aspell -c /path/to/input-file
    comment: |-
      The textual file is displayed in an interactive TUI showing only the parts that contain mispelled words.
    contexts:
      sudo:
      suid:
      unprivileged:
  - binary: false
    code: |-
      aspell --conf /path/to/input-file
    comment: |-
      The first word is likely displayed as error messaged, and converted to lowercase.
    contexts:
      sudo:
      suid:
      unprivileged:
...
