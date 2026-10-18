<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/arp -->
---
functions:
  file-read:
  - binary: false
    code: |-
      arp -v -f /path/to/input-file
    comment: |-
      Lines are likely leaked as error messages.
    contexts:
      sudo:
      suid:
      unprivileged:
...
