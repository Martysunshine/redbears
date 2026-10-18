<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/network/address/get-local-ipv4-addresses.yml -->
rule:
  meta:
    name: get local IPv4 addresses
    namespace: host-interaction/network/address
    authors:
      - moritz.raabe@mandiant.com
      - joakim@intezer.com
      - mehunhoff@google.com
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Discovery::System Network Configuration Discovery [T1016]
    examples:
      - Practical Malware Analysis Lab 05-01.dll_:0x100037e6
      - 4C0553285D724DCAF5909924B4E3E90A:0x402010
  features:
    - or:
      - api: getsockname
      - and:
        - api: GetAdaptersInfo
        - offset: 0x1B0 = IP_ADAPTER_INFO.IpAddressList.IpAddress
        # loop feature?
      - and:
        - api: GetAdaptersAddresses
        - optional:
          - or:
            - number: 0 = AF_UNSPEC
            - number: 2 = AF_INET
            - number: 23 = AF_INET6
