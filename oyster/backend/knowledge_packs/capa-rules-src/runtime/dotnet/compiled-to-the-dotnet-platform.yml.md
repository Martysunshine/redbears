<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/runtime/dotnet/compiled-to-the-dotnet-platform.yml -->
rule:
  meta:
    name: compiled to the .NET platform
    namespace: runtime/dotnet
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: file
    examples:
      - b9f5bd514485fb06da39beff051b9fdc
  features:
    - or:
      - format: dotnet
      - import: mscoree._CorExeMain
      - import: mscoree._corexemain
      - import: mscoree._CorDllMain
      - import: mscoree._cordllmain
