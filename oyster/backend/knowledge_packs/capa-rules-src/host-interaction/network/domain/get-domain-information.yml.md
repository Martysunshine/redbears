<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/network/domain/get-domain-information.yml -->
rule:
  meta:
    name: get domain information
    namespace: host-interaction/network/domain
    authors:
      - awillia2@cisco.com
      - anushka.virgaonkar@mandiant.com
      - mehunhoff@google.com
    description: Detect collection of Windows domain information
    scopes:
      static: instruction
      dynamic: call
    att&ck:
      - Discovery::System Network Configuration Discovery [T1016]
    examples:
      - 9B7CCAA2AE6A5B96E3110EBCBC4311F6:0x1001C184
  features:
    - or:
      - api: netapi32.DsRoleGetPrimaryDomainInformation
      - api: System.DirectoryServices.ActiveDirectory.Domain::GetComputerDomain
      - property/read: System.Net.NetworkInformation.IPGlobalProperties::DomainName
      - property/read: System.Environment::UserDomainName
