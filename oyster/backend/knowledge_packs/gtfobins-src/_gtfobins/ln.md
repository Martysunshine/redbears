<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ln -->
---
functions:
  privilege-escalation:
  - code: |-
      ln -fs /bin/sh /bin/ln
      ln
    comment: |-
      This overrides `ln` itself with a symlink to a shell (or any other executable) that is to be executed as root, useful in case a `sudo` rule allows to only run `ln` by path. Warning, this is a destructive action.
    contexts:
      sudo:
...
