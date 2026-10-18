<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/rust/compiled-with-rust.yml -->
rule:
  meta:
    name: compiled with rust
    namespace: compiler/rust
    authors:
      - "@_re_fox"
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: file
    examples:
      - c3341b7dfbb9d43bca8c812e07b4299f:0x45F490
  features:
    - or:
      - substring: "run with `RUST_BACKTRACE=1` environment variable"
      - substring: "called `Option::unwrap()` on a `None` value"
      - substring: "called `Result::unwrap()` on an `Err` value"
