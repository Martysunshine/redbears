<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/facter -->
---
functions:
  inherit:
  - code: |-
      FACTERLIB=/path/to/dir/ facter
    comment: |-
      The first `.rb` file in the `/path/to/dir/` directory will be executed.
    contexts:
      sudo:
      unprivileged:
    from: ruby
  - code: |-
      facter --custom-dir=/path/to/dir/ x
    comment: |-
      The first `.rb` file in the `/path/to/dir/` directory will be executed.
    contexts:
      sudo:
      unprivileged:
    from: ruby
...
