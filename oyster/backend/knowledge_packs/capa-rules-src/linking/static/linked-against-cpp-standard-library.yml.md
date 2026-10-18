<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/linking/static/linked-against-cpp-standard-library.yml -->
rule:
  meta:
    name: linked against CPP standard library
    namespace: linking/static
    authors:
      - "@mr-tz"
    scopes:
      static: file
      dynamic: file
    references:
      - https://en.wikipedia.org/wiki/P._J._Plauger
      - https://www.dinkumware.com/
    examples:
      - 03b236b23b1ec37c663527c1f53af3fe
  features:
    - or:
      - string: "Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED."
      - string: "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED."
