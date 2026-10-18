<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/data-manipulation/encryption/aes/use-dotnet-library-encryptdecryptutils.yml -->
rule:
  meta:
    name: use .NET library EncryptDecryptUtils
    namespace: data-manipulation/encryption/aes
    authors:
      - "@johnk3r"
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Obfuscated Files or Information [T1027]
    mbc:
      - Anti-Static Analysis::Executable Code Obfuscation [B0032]
    references:
      - https://www.welivesecurity.com/2021/04/06/janeleiro-time-traveler-new-old-banking-trojan-brazil/
    examples:
      - 7f4ba9fc95b30baf8922a6933a4ff1c6a7fef41fae487bb31014c4963357770f
  features:
    - and:
      - match: compiled to the .NET platform
      - string: "RijndaelEncryptDecrypt"
