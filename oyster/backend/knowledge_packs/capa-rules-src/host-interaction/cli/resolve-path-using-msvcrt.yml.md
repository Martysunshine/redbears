<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/cli/resolve-path-using-msvcrt.yml -->
rule:
  meta:
    name: resolve path using msvcrt
    namespace: host-interaction/cli
    authors:
      - "@_re_fox"
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Discovery::File and Directory Discovery [T1083]
    examples:
      - 31600ad0d1a7ea615690df111ae36c73:0x4016B8
  features:
    - or:
      - api: msvcrt.__p__pgmptr
      - api: msvcrt.__p__wpgmptr
      - api: msvcrt._get_pgmptr
      - api: msvcrt._get_wpgmptr
      - api: msvcrt._pgmptr
      - api: msvcrt._wpgmptr
