<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/byebug -->
---
functions:
  inherit:
  - code: |-
      byebug --no-stop /path/to/script.rb
    contexts:
      sudo:
      unprivileged:
    from: ruby
...
