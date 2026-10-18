<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/aws -->
---
functions:
  file-read:
  - binary: false
    code: |-
      aws ec2 describe-instances --filter file:///path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
  inherit:
  - code: |-
      aws help
    contexts:
      sudo:
      unprivileged:
    from: less
...
