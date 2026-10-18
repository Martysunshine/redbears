<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/procmail -->
---
functions:
  command:
  - blind: false
    code: |-
      echo -e ':0\n| /path/to/command >/path/to/temp-file
      procmail -m /path/to/temp-file
    comment: |-
      The program is picky about the file ownership, and waits for some input.
    contexts:
      sudo:
      unprivileged:
...
