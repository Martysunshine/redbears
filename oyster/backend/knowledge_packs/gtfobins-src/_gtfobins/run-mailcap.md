<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/run-mailcap -->
---
functions:
  inherit:
  - code: |-
      run-mailcap --action=view text/plain:/etc/hosts
    contexts:
      sudo:
      unprivileged:
    from: less
  - code: |-
      run-mailcap --action=edit text/plain:/path/to/output-file
    comment: |-
      The file must exist and be not empty.
    contexts:
      sudo:
      unprivileged:
    from: vi
...
