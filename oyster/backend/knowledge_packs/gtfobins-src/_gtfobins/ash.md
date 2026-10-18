<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ash -->
---
functions:
  file-write:
  - code: |-
      ash -c 'echo DATA >/path/to/output-file'
    contexts:
      sudo:
      suid:
        code: |-
          ash -p -c 'echo DATA >/path/to/output-file'
      unprivileged:
  shell:
  - code: |-
      ash
    contexts:
      sudo:
      suid:
        code: |-
          ash -p
      unprivileged:
...
