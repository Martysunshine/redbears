<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/qpdf -->
---
functions:
  file-read:
  - code: |-
      qpdf --empty --add-attachment /path/to/input-file --key=x -- /path/to/output-file
      qpdf --show-attachment=x /path/to/output-file
    contexts:
      sudo:
      suid:
      unprivileged:
...
