<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/apache2ctl -->
---
functions:
  file-read:
  - binary: false
    code: |-
      apache2ctl -c 'Include /path/to/input-file'
    comment: |-
      The first line only is likely leaked as an error message.
    contexts:
      sudo:
      unprivileged:
...
