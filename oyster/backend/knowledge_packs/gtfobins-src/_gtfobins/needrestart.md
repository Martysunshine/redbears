<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/needrestart -->
---
functions:
  inherit:
  - code: |-
      echo '...' >/path/to/temp-file
      needrestart -c /path/to/temp-file
    comment: |-
      This allows to run Perl code (`...`).
    contexts:
      sudo:
      unprivileged:
    from: perl
...
