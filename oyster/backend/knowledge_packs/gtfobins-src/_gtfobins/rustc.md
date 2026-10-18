<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/rustc -->
---
functions:
  file-read:
  - binary: false
    code: |-
      rustc /path/to/input-file
    comment: |-
      The compiler leaks some file lines in the compiler error.
    contexts:
      sudo:
      unprivileged:
  file-write:
  - code: |-
      echo 'fn main() { println!("DATA"); }' >/path/to/temp-file
      rustc /path/to/temp-file -o /path/to/output-file
    comment: |-
      The comment appears in the compiled program.
    contexts:
      sudo:
      unprivileged:
  inherit:
  - code: |-
      rustc --explain E0001
    contexts:
      sudo:
      unprivileged:
    from: less
...
