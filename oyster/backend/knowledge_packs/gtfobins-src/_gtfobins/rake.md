<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/rake -->
---
functions:
  file-read:
  - code: |-
      rake -f /path/to/input-file
    comment: |-
      The file is actually parsed and the first wrong line is returned in an error message.
    contexts:
      sudo:
      unprivileged:
  inherit:
  - code: |-
      rake -p '...'
    comment: |-
      This allows to run Ruby code (`...`).
    contexts:
      sudo:
      unprivileged:
    from: ruby
...
