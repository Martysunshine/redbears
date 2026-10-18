<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/emacs -->
---
comment: |-
  All the functions operate in the Emacs terminal interface.
functions:
  file-read:
  - binary: false
    code: |-
      emacs /path/to/input-file
    contexts:
      sudo:
      unprivileged:
  file-write:
  - binary: false
    code: |-
      emacs /path/to/output-file
      DATA
      C-x C-s
    contexts:
      sudo:
      unprivileged:
  shell:
  - code: |-
      emacs -Q -nw --eval '(term "/bin/sh")'
    contexts:
      sudo:
      unprivileged:
...
