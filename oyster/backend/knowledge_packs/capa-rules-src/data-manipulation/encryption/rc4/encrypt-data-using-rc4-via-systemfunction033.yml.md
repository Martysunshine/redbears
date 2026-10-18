<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/data-manipulation/encryption/rc4/encrypt-data-using-rc4-via-systemfunction033.yml -->
rule:
  meta:
    name: encrypt data using RC4 via SystemFunction033
    namespace: data-manipulation/encryption/rc4
    authors:
      - daniel.stepanic@elastic.co
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Defense Evasion::Obfuscated Files or Information [T1027]
    mbc:
      - Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]
      - Cryptography::Encrypt Data::RC4 [C0027.009]
    references:
      - https://www.redteam.cafe/red-team/shellcode-injection/inmemory-shellcode-encryption-and-decryption-using-systemfunction033
    examples:
      - 0f33c2fec223823f84a732ceb1ad94ed2645e896095144850cf1443aeda67da6:0x180001000 # api match
  features:
    - or:
      - api: SystemFunction033
      - basic block:
        - and:
          - match: link function at runtime on Windows
          - string: "SystemFunction033"
          - optional:
            - string: /advapi32/i
            - string: /cryptsp/i
