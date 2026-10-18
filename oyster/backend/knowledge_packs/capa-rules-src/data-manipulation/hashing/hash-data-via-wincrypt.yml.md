<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/data-manipulation/hashing/hash-data-via-wincrypt.yml -->
rule:
  meta:
    name: hash data via WinCrypt
    namespace: data-manipulation/hashing
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Cryptography::Cryptographic Hash [C0029]
    examples:
      - 03B236B23B1EC37C663527C1F53AF3FE:0x18002E46B
  features:
    - and:
      - api: advapi32.CryptHashData
      - optional:
        - basic block:
          - and:
            - api: advapi32.CryptGetHashParam
            - or:
              - number: 1 = HP_ALGID
              - number: 2 = HP_HASHVAL
              - number: 4 = HP_HASHSIZE
        - call:
          - and:
            - api: advapi32.CryptGetHashParam
            - or:
              - number: 1 = HP_ALGID
              - number: 2 = HP_HASHVAL
              - number: 4 = HP_HASHSIZE
