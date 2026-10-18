<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/linking/static/aplib/linked-against-aplib.yml -->
rule:
  meta:
    name: linked against aPLib
    namespace: linking/static/aplib
    authors:
      - still@teamt5.org
    scopes:
      static: file
      dynamic: file
    mbc:
      - Data::Compression Library [C0060]
    examples:
      - 72c8e3c8049927fa1dd53b61d9b67b9d74ab5b6c030bc38dfbe9a338a32438c9
  features:
    - or:
      - string: /aPLib v.* the smaller the better/
