<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/readelf -->
---
functions:
  file-read:
  - binary: false
    code: |-
      readelf -a @/path/to/input-file
    comment: |-
      Each line is corrupted by a prefix string and wrapped inside single quotes. Also consider that lines are actually parsed as `readelf` options thus some file contents may lead to unexpected results.
    contexts:
      sudo:
      suid:
      unprivileged:
...
