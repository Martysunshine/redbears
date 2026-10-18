<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/data-manipulation/svg/use-dotnet-library-sharpvectors.yml -->
rule:
  meta:
    name: use .NET library SharpVectors
    namespace: data-manipulation/svg
    authors:
      - "@johnk3r"
    scopes:
      static: file
      dynamic: file
    references:
      - https://www.welivesecurity.com/2021/04/06/janeleiro-time-traveler-new-old-banking-trojan-brazil/
    examples:
      - 387f15043f0198fd3a637b0758c2b6dde9ead795c3ed70803426fc355731b173
  features:
    - and:
      - match: compiled to the .NET platform
      - string: "SharpVectors.Converters.Wpf"
