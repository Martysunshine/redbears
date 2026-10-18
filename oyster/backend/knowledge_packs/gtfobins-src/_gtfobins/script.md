<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/script -->
---
functions:
  file-write:
  - binary: false
    code: |-
      script -q -c '# DATA' /path/to/output-file
    comment: |-
      The content appears among the log prints.
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      script -q /dev/null
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
