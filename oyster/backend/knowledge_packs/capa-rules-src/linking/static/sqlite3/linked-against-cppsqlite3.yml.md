<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/linking/static/sqlite3/linked-against-cppsqlite3.yml -->
rule:
  meta:
    name: linked against CppSQLite3
    namespace: linking/static/sqlite3
    authors:
      - still@teamt5.org
    scopes:
      static: file
      dynamic: file
    examples:
      - 253309d8b3675d3cc61d4bf23aa15d4b
  features:
    - and:
      - substring: "CppSQLite3DB"
      - substring: "CppSQLite3Query"
