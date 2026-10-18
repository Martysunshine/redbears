<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/files/list/enumerate-files-recursively.yml -->
rule:
  meta:
    name: enumerate files recursively
    namespace: host-interaction/file-system/files/list
    authors:
      - "@_re_fox"
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: unsupported
    att&ck:
      - Discovery::File and Directory Discovery [T1083]
    mbc:
      - Discovery::File and Directory Discovery [E1083]
    examples:
      - 5f66b82558ca92e54e77f216ef4c066c:0x40640E
  features:
    - and:
      - or:
        - match: enumerate files on Windows
        - match: enumerate files on Linux
      - characteristic: recursive call
