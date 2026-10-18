<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/network/connectivity/check-internet-connectivity-via-wininet.yml -->
rule:
  meta:
    name: check Internet connectivity via WinINet
    namespace: host-interaction/network/connectivity
    authors:
      - matthew.williams@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: unsupported  # requires mnemonic features
    att&ck:
      - Discovery::System Network Configuration Discovery::Internet Connection Discovery [T1016.001]
    examples:
      - 648FC498110B11B4313A47A776E6BA40:0x6633F0
  features:
    - or:
      - and:
        - or:
          - api: wininet.InternetGetConnectedState
          - api: wininet.InternetCheckConnection
        - optional:
          - instruction:
            - mnemonic: cmp
            - or:
              - number: 0 = FALSE
              - number: 1 = TRUE
      - api: wininet.InternetAttemptConnect
