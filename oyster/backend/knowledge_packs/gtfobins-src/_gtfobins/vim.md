<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/vim -->
---
functions:
  file-read:
  - binary: false
    code: |-
      vim -c ':redir! >/path/to/output-file | echo "DATA" | redir END | q'
    contexts:
      sudo:
      suid:
      unprivileged:
  inherit:
  - code: |-
      vim -c ':py ...'
    comment: |-
      This allows to run Python code (`...`).
    contexts:
      sudo:
      suid:
      unprivileged:
    from: python
  - code: |-
      vim -c ':lua ...'
    comment: |-
      This allows to run Lua code (`...`).
    contexts:
      sudo:
      suid:
      unprivileged:
    from: lua
  - code: |-
      vim
    contexts:
      sudo:
      suid:
      unprivileged:
    from: vi
...
