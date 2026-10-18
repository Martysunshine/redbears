<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ksshell -->
---
functions:
  file-read:
  - code: |-
      ksshell -i /path/to/input-file
    comment: |-
      Each line is corrupted by a prefix string. Also consider that lines are actually parsed as `kickstart` scripts thus some file contents may lead to unexpected results.
    contexts:
      sudo:
      suid:
      unprivileged:
...
