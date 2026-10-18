<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/linking/static/zlib/linked-against-zlib.yml -->
rule:
  meta:
    name: linked against ZLIB
    namespace: linking/static/zlib
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: file
    mbc:
      - Data::Compression Library [C0060]
    examples:
      - 6cc148363200798a12091b97a17181a1
  features:
    - or:
      - string: /deflate .* Copyright/
      - string: /inflate .* Copyright/
