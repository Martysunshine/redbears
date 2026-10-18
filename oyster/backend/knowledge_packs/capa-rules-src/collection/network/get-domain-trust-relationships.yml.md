<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/network/get-domain-trust-relationships.yml -->
rule:
  meta:
    name: get domain trust relationships
    namespace: collection/network
    authors:
      - johnk3r
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::Domain Trust Discovery [T1482]
    examples:
      - 0796f1c1ea0a142fc1eb7109a44c86cb:0x40222F
      - 0731679c5f99e8ee65d8b29a3cabfc6b:0x40408E
  features:
    - or:
      - and:
        - string: /nltest/i
        - or:
          - string: /\/domain_trusts/i
          - string: /\/dclist/i
          - string: /\/all_trusts/i
      - api: DsEnumerateDomainTrusts
