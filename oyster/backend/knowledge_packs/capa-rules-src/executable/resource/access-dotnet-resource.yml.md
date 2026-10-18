<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/executable/resource/access-dotnet-resource.yml -->
rule:
  meta:
    name: access .NET resource
    namespace: executable/resource
    authors:
      - "@mr-tz"
    scopes:
      static: function
      dynamic: span of calls
    examples:
      - 387f15043f0198fd3a637b0758c2b6dde9ead795c3ed70803426fc355731b173:0x06000084
  features:
    - and:
      - format: dotnet
      - or:
        - api: System.Resources.ResourceManager::ctor
        - api: System.Reflection.Assembly::GetManifestResourceStream
