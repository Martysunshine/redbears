<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/pwsh -->
---
functions:
  file-write:
  - code: |-
      pwsh -c '"DATA" | Out-File /path/to/output-file'
    contexts:
      sudo:
      unprivileged:
  shell:
  - code: |-
      pwsh
    contexts:
      sudo:
      unprivileged:
...
