<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/data-manipulation/encryption/import-public-key.yml -->
rule:
  meta:
    name: import public key
    namespace: data-manipulation/encryption
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Cryptography::Encryption Key::Import Public Key [C0028.001]
    examples:
      - ffeae4a391a1d5203bd04b4161557227:0x4047A0
  features:
    - and:
      - api: advapi32.CryptAcquireContext
      - api: crypt32.CryptImportPublicKeyInfo
      - optional:
        - and:
          - api: crypt32.CryptStringToBinary
          - api: crypt32.CryptDecodeObjectEx
