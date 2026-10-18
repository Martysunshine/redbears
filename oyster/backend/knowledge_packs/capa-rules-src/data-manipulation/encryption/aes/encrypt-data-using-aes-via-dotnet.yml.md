<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/data-manipulation/encryption/aes/encrypt-data-using-aes-via-dotnet.yml -->
rule:
  meta:
    name: encrypt data using AES via .NET
    namespace: data-manipulation/encryption/aes
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: unsupported  # requires class features
    att&ck:
      - Defense Evasion::Obfuscated Files or Information [T1027]
    mbc:
      - Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]
      - Cryptography::Encrypt Data::AES [C0027.001]
    examples:
      - b9f5bd514485fb06da39beff051b9fdc
  features:
    - and:
      - class: System.Security.Cryptography.RijndaelManaged
      - class: System.Security.Cryptography.CryptoStream
