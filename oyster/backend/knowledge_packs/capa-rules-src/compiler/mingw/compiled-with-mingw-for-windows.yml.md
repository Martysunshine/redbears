<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/mingw/compiled-with-mingw-for-windows.yml -->
rule:
  meta:
    name: compiled with MinGW for Windows
    namespace: compiler/mingw
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: file
    examples:
      - 5b3968b47eb16a1cb88525e3b565eab1
  features:
    - and:
      - string: "Mingw runtime failure:"
      - string: "_Jv_RegisterClasses"
        description: from GCC
