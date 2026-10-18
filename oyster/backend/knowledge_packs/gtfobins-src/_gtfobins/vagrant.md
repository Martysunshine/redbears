<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/vagrant -->
---
functions:
  inherit:
  - code: |-
      echo '...' >Vagrantfile
      vagrant up
    comment: |-
      This allows to run Ruby code (`...`).
    contexts:
      sudo:
      unprivileged:
    from: ruby
...
