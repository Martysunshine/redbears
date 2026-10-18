<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/network/connectivity/check-internet-connectivity-in-dotnet.yml -->
rule:
  meta:
    name: check Internet connectivity in .NET
    namespace: host-interaction/network/connectivity
    authors:
      - omurcankaya@protonmail.com
    scopes:
      static: instruction
      dynamic: call
    att&ck:
      - Discovery::System Network Configuration Discovery::Internet Connection Discovery [T1016.001]
    references:
      - https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.networkinterface.getisnetworkavailable?view=net-10.0
    examples:
      - e8ea789b860e8354b3ef5058bea7ea98:0x06000002
  features:
    - and:
      - api: System.Net.NetworkInformation.NetworkInterface::GetIsNetworkAvailable
      - format: dotnet
