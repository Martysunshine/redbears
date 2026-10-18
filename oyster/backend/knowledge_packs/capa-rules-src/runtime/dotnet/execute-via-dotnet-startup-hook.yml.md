<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/runtime/dotnet/execute-via-dotnet-startup-hook.yml -->
rule:
  meta:
    name: execute via .NET startup hook
    namespace: runtime/dotnet
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: unsupported  # requires function-name features
    references:
      - https://rastamouse.me/net-startup-hooks/
      - https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md
    examples:
      - 1ee70f829fa4f21b97fea53412383b4c83be1aaf8bab2f4b692549f8ceb4388f
  features:
    - and:
      - format: dotnet
      - function-name: "StartupHook::Initialize"
