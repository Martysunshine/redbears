<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-debugging/check-for-time-delay-in-dotnet.yml -->
rule:
  meta:
    name: check for time delay in .NET
    namespace: anti-analysis/anti-debugging
    authors:
      - "@aryanyk"
    description: detects potential debugger checks by comparing Environment.TickCount values around Thread.Sleep calls.
    scopes:
      static: function
      dynamic: unsupported  # relies on static analysis of IL property access and timing patterns
    att&ck:
      - Defense Evasion::Virtualization/Sandbox Evasion [T1497]
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection::Timing/Delay Check GetTickCount [B0001.032]
    references:
      - https://github.com/Outbuilt/.NET-Anti-Debug
    examples:
      - e842958188274d5ffee7fbeffb803b2e:0x6000001
  features:
    - and:
      - format: dotnet
      - api: System.Threading.Thread::Sleep
      - count(property(System.Environment::TickCount)): 2 or more
