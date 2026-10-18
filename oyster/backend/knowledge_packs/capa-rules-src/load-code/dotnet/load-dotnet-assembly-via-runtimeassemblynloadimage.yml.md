<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/load-code/dotnet/load-dotnet-assembly-via-runtimeassemblynloadimage.yml -->
rule:
  meta:
    name: load .NET assembly via RuntimeAssembly.nLoadImage
    namespace: load-code/dotnet
    authors:
      - still@teamt5.org
    scopes:
      static: file
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Reflective Code Loading [T1620]
    references:
      - https://dr4k0nia.github.io/posts/NixImports-a-NET-loader-using-HInvoke/
    examples:
      - 6c8b0f234a239eb76c80b6e5b911720dfcd3738ff410375fbc65030c1f8fefe1
  features:
    - and:
      - format: dotnet
      - string: "nLoadImage"
      - match: invoke .NET assembly method
