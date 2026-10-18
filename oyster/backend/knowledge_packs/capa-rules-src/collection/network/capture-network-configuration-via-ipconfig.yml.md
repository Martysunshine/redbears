<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/network/capture-network-configuration-via-ipconfig.yml -->
rule:
  meta:
    name: capture network configuration via ipconfig
    namespace: collection/network
    authors:
      - "@_re_fox"
    scopes:
      static: basic block
      dynamic: span of calls
    att&ck:
      - Discovery::System Network Configuration Discovery [T1016]
    examples:
      - 7204e3efc2434012e13ca939db0d0b02:0x403028
  features:
    - and:
      - string: /ipconfig(\.exe)?/i
      - api: msvcr100.system
      - optional:
        - and:
          - string: "ipconfig.txt"
          - substring: "[Windows IP Configuration]"
            description: Arkei Stealer Filename and Banner
