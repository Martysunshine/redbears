<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/systemd-run -->
---
functions:
  command:
  - blind: true
    code: |-
      systemd-run /path/to/command
    contexts:
      sudo:
  shell:
  - code: |-
      systemd-run -S
    contexts:
      sudo:
  - code: |-
      systemd-run -t /bin/sh
    contexts:
      sudo:
...
