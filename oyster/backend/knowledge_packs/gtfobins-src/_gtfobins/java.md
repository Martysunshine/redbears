<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/java -->
---
functions:
  shell:
  - code: |-
      java Shell
    comment: |-
      The `Shell.class` class file can be compiled offline, then uploaded to the target:

      ```
      cat >Shell.java <<EOF
      public class Shell {
          public static void main(String[] args) throws Exception {
              new ProcessBuilder("/bin/sh").inheritIO().start().waitFor();
          }
      }
      EOF

      javac Shell.java
      ```
    contexts:
      sudo:
      unprivileged:
...
