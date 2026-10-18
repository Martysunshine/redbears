<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/duplicate-stdin-and-stdout.yml -->
rule:
  meta:
    name: duplicate stdin and stdout
    authors:
      - joakim@intezer.com
    lib: true
    scopes:
      static: basic block
      dynamic: call
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x40236D
  features:
    - and:
      - or:
        - os: linux
        - os: android
      - api: dup2
      - number: 0 = STDIN
      - number: 1 = STDOUT
