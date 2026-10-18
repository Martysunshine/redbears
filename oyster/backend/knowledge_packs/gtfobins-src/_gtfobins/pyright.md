<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pyright -->
---
functions:
  file-read:
  - binary: false
    code: |-
      pyright /path/to/input-file
    comment: |-
      Content is leaked as error messages.
    contexts:
      sudo:
      unprivileged:
  - binary: false
    code: |-
      pyright --outputjson /path/to/input-file
    comment: |-
      Content is leaked as error messages in JSON format.
    contexts:
      sudo:
      unprivileged:
  - code: |-
      pyright -w /path/to/input-dir/
    comment: |-
      Recursively walks directories, parsing all Python files and leaking some contents through diagnostics.
    contexts:
      sudo:
      unprivileged:
...
