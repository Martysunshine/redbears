<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/cowsay -->
---
functions:
  inherit:
  - code: |-
      cowsay -f /path/to/script.pl x
    contexts:
      sudo:
      unprivileged:
    from: perl
...
