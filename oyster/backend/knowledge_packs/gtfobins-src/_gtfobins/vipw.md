<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/vipw -->
---
functions:
  inherit:
  - code: |-
      vipw
    comment: |-
      Despite requiring superuser privileges to run, the editor is executed as the unprivileged user.
    contexts:
      sudo:
      suid:
    from: vi
...
