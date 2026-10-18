<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/delphi/compiled-with-borland-delphi.yml -->
rule:
  meta:
    name: compiled with Borland Delphi
    namespace: compiler/delphi
    authors:
      - william.ballenthin@mandiant.com
      - "@mr-tz"
    scopes:
      static: file
      dynamic: file
    examples:
      - 4BDD67FF852C221112337FECD0681EAC
  features:
    - or:
      - string: "Borland C++ - Copyright 2002 Borland Corporation"
      - string: "Sysutils::Exception"
      - string: "TForm1"
      - import: "BORLNDMM.DLL"
      - substring: "SOFTWARE\\Borland\\Delphi\\RTL"
      - substring: "Embarcadero Delphi for Win32 compiler"
